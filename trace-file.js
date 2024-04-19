///<reference path='C:\\Users\\r0th3r\\OneDrive\\Code\\index.d.ts'/>



var cfg = {
    preview_length: -1, // `-1` for all
    opened_files: new Map/*<NativePointer, String>*/(), // <FileHandle, FileName>
};


function has_name(hObject) {
    let hFile = Number(hObject);
    return cfg.opened_files.has(hFile) ? 
        `\"${cfg.opened_files.get(hFile)}\"` : hObject.toString(16);
}

function current_pointer(hFile) {
    const FILE_CURRENT = 1;
    let lpliNew = Memory.alloc(8);

    return new NativeFunction(
        Module.getExportByName('kernel32.dll', 'SetFilePointerEx'),
        'bool', ['pointer', 'int64', 'pointer', 'int32'])
        (hFile, 0, lpliNew, FILE_CURRENT) ? lpliNew.readS64() : 0;
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
            let lpObjectAttributes = args[2];
            if (lpObjectAttributes.equals(NULL)) return;

            let ObjectName = lpObjectAttributes.add(2 * Process.pointerSize).readPointer();
            if (ObjectName.equals(NULL) && 0 == ObjectName.add(0).readU16()) return;

            let Buffer = ObjectName.add(Process.pointerSize).readPointer();
            this.filename = Buffer.readUtf16String();
        }
    },
    onLeave: function (retval) {
        /* STATUS_SUCCESS */
        if (!retval.equals(0)) return;

        let FileHandle = this.lpFileHandle.readPointer();

        /* INVALID_HANDLE_VALUE */
        if (FileHandle.equals(-1) || FileHandle.equals(0)) return;

        cfg.opened_files.set(Number(FileHandle), this.filename);

        console.log(`open(${has_name(FileHandle)}) -> ${FileHandle.toString(16)}`);
    }
});

Interceptor.attach(Module.getExportByName('kernel32.dll', 'ReadFile'), {
    onEnter: function (args) {
        this.currentPointer = current_pointer(args[0]);
        this.hFile = args[0];

        this.bufferSize = Number(args[2]); this.pbufferSize = args[3];

        this.buffer = args[1];
    },
    onLeave: function (retval) {
        if (retval.equals(0)) return;

        let realBufferSize = this.pbufferSize.equals(0)
            ? this.bufferSize : this.pbufferSize.readU32();

        console.log(
            `read<${this.currentPointer.toString(16)}>` + 
            `(${has_name(this.hFile)}, ` + 
            `..., ${this.bufferSize}, ${realBufferSize})`);

        if (0 === realBufferSize || 0 === cfg.preview_length) return;

        console.log(
            hexdump(this.buffer.readByteArray(-1 === cfg.preview_length ? realBufferSize : cfg.preview_length),
            { offset: 0, header: false, ansi: true }));
    }
});

Interceptor.attach(Module.getExportByName('kernel32.dll', 'WriteFile'), {
    onEnter: function (args) {
        this.currentPointer = current_pointer(args[0]);
        this.hFile = args[0];

        this.bufferSize = Number(args[2]); this.pbufferSize = args[3];

        this.buffer = args[1];
    },
    onLeave: function (retval) {
        if (retval.equals(0)) return;

        let realBufferSize = this.pbufferSize.equals(0)
            ? this.bufferSize : this.pbufferSize.readU32();

        console.log(
            `write<${this.currentPointer.toString(16)}>` + 
            `(${has_name(this.hFile)}, ` + 
            `..., ${this.bufferSize}, ${realBufferSize})`);

        if (0 === realBufferSize || 0 === cfg.preview_length) return;

        console.log(
            hexdump(this.buffer.readByteArray(-1 === cfg.preview_length ? realBufferSize : cfg.preview_length),
            { offset: 0, header: false, ansi: true }));
    }
});


// Interceptor.attach(Module.getExportByName('kernel32.dll', 'DeviceIoControl'), {
//     onEnter: function (args) {
//         this.hFile = args[0];

//         this.ioctl = Number(args[1]);
//         this.inBufferSize = Number(args[3]);
//         this.outBufferSize = Number(args[5]); this.pbufferSize = args[6];

//         this.inBuffer = args[2]; this.outBuffer = args[4];
//     },
//     onLeave: function (retval) {
//         if (retval.equals(0)) return;

//         let realBufferSize = this.pbufferSize.equals(0)
//             ? this.outBufferSize : this.pbufferSize.readU32();

//         console.log(
//             `ioctl(${has_name(this.hFile)}, ` +
//             `${this.ioctl.toString(16)}, ` + 
//             `..., ${this.inBufferSize}, ..., ${this.outBufferSize}, ${realBufferSize})`);

//         if (0 === cfg.preview_length) return;

//         /* IN */
//         if (0 < this.inBufferSize) {
//             console.log(
//                 hexdump(this.inBuffer.readByteArray(-1 === cfg.preview_length ? this.inBufferSize : cfg.preview_length),
//                 { offset: 0, header: false, ansi: true }));
//         } else console.log('IN:  NaN')

//         console.log('--------------------------------' + '--------------------------------');

//         /* OUT */
//         if (0 < realBufferSize) {
//             console.log(
//                 hexdump(this.outBuffer.readByteArray(-1 === cfg.preview_length ? realBufferSize : cfg.preview_length),
//                 { offset: 0, header: false, ansi: true }));
//         } else console.log('OUT:  NaN')
//     }
// });
