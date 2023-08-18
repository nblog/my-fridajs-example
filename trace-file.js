///<reference path='C:\\Users\\r0th3r\\OneDrive\\Code\\index.d.ts'/>


const view_length = 16; // view length of buffer
var opened_files = new Map/*<Number, String>*/(); // <FileHandle, FileName>


function has_name(hObject) {
    let hFile = Number(hObject);
    return opened_files.has(hFile) ? 
        `\"${opened_files.get(hFile)}\"` : hFile.toString(16);
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

        let hFile = Number(this.hObject);
        if (opened_files.has(hFile)) opened_files.delete(hFile);
    }
});

// Interceptor.attach(Module.getExportByName('kernelbase.dll', 'CreateFileW'), {
//     onEnter: function (args) {
//         this.filename = args[0].readUtf16String();
//     },
//     onLeave: function (retval) {
//         if (retval.equals(0) || retval.equals(-1)) return;

//         let hFile = Number(retval);
//         opened_files.set(hFile, this.filename);
//     }
// });

Interceptor.attach(Module.getExportByName('ntdll.dll', 'ZwCreateFile'), {
    onEnter: function (args) {
        this.lpFileHandle = args[0];

        let lpObjectAttributes = args[2];
        if (!lpObjectAttributes.equals(NULL)) {
            let ObjectName = lpObjectAttributes.add(2 * Process.pointerSize).readPointer();
            if (!ObjectName.equals(NULL) && ObjectName.add(0).readU16()) {
                let Buffer = ObjectName.add(Process.pointerSize).readPointer();
                this.filename = Buffer.readUtf16String();
            }
        }
    },
    onLeave: function (retval) {
        /* STATUS_SUCCESS */
        if (!retval.equals(0)) return;
        let FileHandle = this.lpFileHandle.readPointer();

        if (FileHandle.equals(0) || FileHandle.equals(-1)) return;

        let hFile = Number(FileHandle);
        opened_files.set(hFile, this.filename);
    }
});

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

        let filename = has_name(this.hFile);

        let realBufferSize = this.pbufferSize.equals(0)
            ? this.outBufferSize : this.pbufferSize.readU32();

        console.log(`ioctl(${filename}, ` +
        `${this.ioctl.toString(16)}, ` + 
        `..., ${this.inBufferSize}, ..., ${this.outBufferSize}, ${realBufferSize})` )
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

        let filename = has_name(this.hFile);

        let realBufferSize = this.pbufferSize.equals(0)
            ? this.bufferSize : this.pbufferSize.readU32();

        console.log(
            `read<${this.currentPointer.toString(16)}>` + 
            `(${filename}, ..., ${this.bufferSize}, ${realBufferSize})`);

        if (view_length) {
            console.log(
                hexdump(this.buffer.readByteArray(view_length), 
                { offset: 0, length: view_length, header: false, ansi: true }));
        }
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

        let filename = has_name(this.hFile);

        let realBufferSize = this.pbufferSize.equals(0)
            ? this.bufferSize : this.pbufferSize.readU32();

        console.log(
            `write<${this.currentPointer.toString(16)}>` + 
            `(${filename}, ..., ${this.bufferSize}, ${realBufferSize})`);

        if (view_length) {
            console.log(
                hexdump(this.buffer.readByteArray(view_length), 
                { offset: 0, length: view_length, header: false, ansi: true }));
        }
    }
});
