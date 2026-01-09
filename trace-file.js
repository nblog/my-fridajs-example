///<reference path='C:/Users/r0th3r/OneDrive/Code/index.d.ts'/>


class utils {
    static current_pointer(hFile) {
        const FILE_CURRENT = 1;
        const lpliNew = Memory.alloc(8);
        lpliNew.writeS64(0);

        return new NativeFunction(
            Module.getExportByName('kernel32.dll', 'SetFilePointerEx'),
            'bool', ['pointer', 'int64', 'pointer', 'int32'])
            (hFile, 0, lpliNew, FILE_CURRENT) ? lpliNew.readS64() : 0;
    }
    /* https://learn.microsoft.com/windows/win32/memory/obtaining-a-file-name-from-a-file-handle */
    static try_get_file_name(hFile) {
        const MAX_PATH = 260;
        const lpFileName = Memory.alloc(MAX_PATH * 2);
        const GetFinalPathNameByHandleW = new NativeFunction(
            Module.getExportByName('kernel32.dll', 'GetFinalPathNameByHandleW'),
            'uint32', ['pointer', 'pointer', 'uint32', 'uint32']);
        GetFinalPathNameByHandleW(hFile, lpFileName, MAX_PATH, 0/*FILE_NAME_NORMALIZED*/);
        return lpFileName.readUtf16String() || '';
    }
}

var cfg = {
    preview_length: 0, // `-1` for all
    opened_files: new Map/*<NativePointer, String>*/(), /*<FileHandle, FileName>*/
    has_name: function (hFile) {
        return utils.try_get_file_name(hFile) 
        || cfg.opened_files.get(Number(hFile)) 
        || hFile.toString(16);
    }
};

class UNICODE_STRING {
    constructor(UString=NULL) {
        this.Length = 0;
        this.MaximumLength = 0;
        this.Buffer = NULL;

        if (!UString || UString.isNull()) return;

        this.Length = UString.add(0).readU16();
        this.MaximumLength = UString.add(2).readU16();
        this.Buffer = UString.add(Process.pointerSize).readPointer();
    }
    toString() {
        if (this.Length === 0 || this.Buffer.isNull()) return '';
        return this.Buffer.readUtf16String() || '';
    }
}

Interceptor.attach(Module.getExportByName('kernel32.dll', 'CloseHandle'), {
    onEnter: function (args) {
        this.hObject = args[0];
    },
    onLeave: function (retval) {
        if (retval.equals(0)) return;
        cfg.opened_files.delete(Number(this.hObject));
    }
});

Interceptor.attach(Module.getExportByName('ntdll.dll', 'ZwCreateFile'), {
    onEnter: function (args) {
        this.lpFileHandle = args[0];

        {
            const lpObjectAttributes = args[2];
            if (lpObjectAttributes.equals(NULL)) return;

            const OBJECT_ATTRIBUTES = {
                Length: lpObjectAttributes.add(0 * Process.pointerSize).readU32(),
                ObjectName: lpObjectAttributes.add(2 * Process.pointerSize).readPointer(),
            };

            this.FileName = new UNICODE_STRING(OBJECT_ATTRIBUTES.ObjectName);
        }
    },
    onLeave: function (retval) {
        /* STATUS_SUCCESS */
        if (!retval.equals(0)) return;

        const FileHandle = this.lpFileHandle.readPointer();

        /* INVALID_HANDLE_VALUE */
        if (FileHandle.equals(-1) || FileHandle.equals(0)) return;

        cfg.opened_files.set(Number(FileHandle), this.FileName.toString());

        console.log(`open(${cfg.has_name(FileHandle)}) -> ${FileHandle.toString(16)}`);
    }
});

Interceptor.attach(Module.getExportByName('kernel32.dll', 'ReadFile'), {
    onEnter: function (args) {
        this.currentPointer = utils.current_pointer(args[0]);
        this.hFile = args[0];

        this.bufferSize = Number(args[2]); this.pbufferSize = args[3];

        this.buffer = args[1];
    },
    onLeave: function (retval) {
        if (retval.equals(0)) return;

        const realBufferSize = this.pbufferSize.equals(0)
            ? this.bufferSize : this.pbufferSize.readU32();

        console.log(
            `read<${this.currentPointer.toString(16)}>` + 
            `(${cfg.has_name(this.hFile)}, ` + 
            `..., ${this.bufferSize}, ${realBufferSize})`);

        if (0 === realBufferSize || 0 === cfg.preview_length) return;

        console.log(
            hexdump(this.buffer.readByteArray(-1 === cfg.preview_length ? realBufferSize : Math.min(cfg.preview_length, realBufferSize)),
            { offset: 0, header: false, ansi: true }));
    }
});

Interceptor.attach(Module.getExportByName('kernel32.dll', 'WriteFile'), {
    onEnter: function (args) {
        this.currentPointer = utils.current_pointer(args[0]);
        this.hFile = args[0];

        this.bufferSize = Number(args[2]); this.pbufferSize = args[3];

        this.buffer = args[1];
    },
    onLeave: function (retval) {
        if (retval.equals(0)) return;

        const realBufferSize = this.pbufferSize.equals(0)
            ? this.bufferSize : this.pbufferSize.readU32();

        console.log(
            `write<${this.currentPointer.toString(16)}>` + 
            `(${cfg.has_name(this.hFile)}, ` + 
            `..., ${this.bufferSize}, ${realBufferSize})`);

        if (0 === realBufferSize || 0 === cfg.preview_length) return;

        console.log(
            hexdump(this.buffer.readByteArray(-1 === cfg.preview_length ? realBufferSize : Math.min(cfg.preview_length, realBufferSize)),
            { offset: 0, header: false, ansi: true }));
    }
});

/*
Interceptor.attach(Module.getExportByName('kernel32.dll', 'DeviceIoControl'), {
    onEnter: function (args) {
        this.hFile = args[0];

        this.ioctl = Number(args[1]);
        this.inBufferSize = Number(args[3]);
        this.outBufferSize = Number(args[5]); this.pbufferSize = args[6];

        this.inBuffer = args[2]; this.outBuffer = args[4];
    },
    onLeave: function (retval) {
        if (retval.equals(0)) return;

        const realBufferSize = this.pbufferSize.equals(0)
            ? this.outBufferSize : this.pbufferSize.readU32();

        console.log(
            `ioctl(${cfg.has_name(this.hFile)}, ` +
            `${this.ioctl.toString(16)}, ` + 
            `..., ${this.inBufferSize}, ..., ${this.outBufferSize}, ${realBufferSize})`);

        if (0 === cfg.preview_length) return;

        if (0 < this.inBufferSize) {
            console.log('IN:  \n' +
                hexdump(this.inBuffer.readByteArray(-1 === cfg.preview_length ? this.inBufferSize : Math.min(cfg.preview_length, this.inBufferSize)),
                { offset: 0, header: false, ansi: true }));
        } else console.log('IN:  NaN')

        console.log('--------------------------------' + '--------------------------------');

        if (0 < realBufferSize) {
            console.log('OUT:  \n' +
                hexdump(this.outBuffer.readByteArray(-1 === cfg.preview_length ? realBufferSize : Math.min(cfg.preview_length, realBufferSize)),
                { offset: 0, header: false, ansi: true }));
        } else console.log('OUT:  NaN')
    }
});
*/
