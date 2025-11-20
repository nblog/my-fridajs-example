///<reference path='C:\Users\r0th3r\OneDrive\Code\index.d.ts'/>


function rndint(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1)) + min;
}


function rain() {
    const pzcls = ptr(0x6a9ec0).readPointer().add(0x768).readPointer();

    const drop = new NativeFunction(
        Process.mainModule.base.add(0xCB10), 
        'void', ['pointer', 'uint', 'uint', 'uint', 'uint'], 'thiscall');

    for (let index = 0; index < 50; index++) {
        drop(pzcls, rndint(200, 600), 0x3c, 6, 0);
    }
}


function putprop(x=0, y=0, id=35) {
    const pzcls = ptr(0x6a9ec0).readPointer().add(0x768);

    const myCode = Memory.alloc(Process.pageSize);
    Memory.patchCode(myCode, Process.pageSize, code => {
        const cw = new X86Writer(code, { pc: myCode });
        cw.putPushU32(-1);
        cw.putPushU32(id);
        cw.putPushU32(x);
        cw.putMovRegU32('eax', y);
        cw.putPushImmPtr(pzcls);
        cw.putCallAddress(Process.mainModule.base.add(0xD120));
        cw.putRet();
        cw.flush();
    });
    new NativeFunction(myCode, 'void', [])();
}


function boom(range=3) {
    for (let index = 0; index < range; index++) {
        putprop(3, 2, 18);
    }
    putprop(3, 2, 22);

    for (let y = 0; y < 6; y++) {
        for (let index = 0; index < 3; index++)
            putprop(0, y, 0x7d);
    }
}

class sunlight {
    constructor(){
        this.target = Process.mainModule.base
        .add(0x2a9ec0).readPointer()
        .add(0x768).readPointer()
        .add(0x5560);
    }

    get value() {
        return this.target.readU32();
    }
    set value(val) {
        this.target.writeU32(val);
    }
}


rpc.exports = {
    rain, boom
};



class plantsvszombies {
    static target() {
        const FindWindow = new NativeFunction(
            Module.getExportByName('user32.dll', 'FindWindowW'), 
            'pointer', ['pointer', 'pointer']);
        return FindWindow(Memory.allocUtf16String('MainWindow'), NULL);
    }

    hWnd = plantsvszombies.target();

    get unicode() {
        const IsWindowUnicode = new NativeFunction(
            Module.getExportByName('user32.dll', 'IsWindowUnicode'), 
            'bool', ['pointer']);
        return Boolean(IsWindowUnicode(this.hWnd));
    }

    get WndProc() {
        /*
        const GetClassLongPtrW = new NativeFunction(
            Module.getExportByName('user32.dll', 'GetClassLongW'),
            'pointer', ['pointer', 'int']);
        const GetClassLongPtrA = new NativeFunction(
            Module.getExportByName('user32.dll', 'GetClassLongA'),
            'pointer', ['pointer', 'int']);
        const GCLP_WNDPROC = -24;
        let WndProc1 = GetClassLongPtrW(this.hWnd, GCLP_WNDPROC);
        if (WndProc1.shr(16).equals(0xffff) ) {
            WndProc1 = GetClassLongPtrA(this.hWnd, GCLP_WNDPROC);
        }
        */

        const GetWindowLongPtr = new NativeFunction(
            Module.getExportByName('user32.dll', 
                this.unicode ? 'GetWindowLongW' : 'GetWindowLongA'), 
            'pointer', ['pointer', 'int']);
        const GWLP_WNDPROC = -4;
        let WndProc1 = GetWindowLongPtr(this.hWnd, GWLP_WNDPROC);

        if (WndProc1.isNull())
            if (this.unicode)
                WndProc1 = Module.getExportByName('user32.dll', 'DefWindowProcW');
            else
                WndProc1 = Module.getExportByName('user32.dll', 'DefWindowProcA');

        return new NativeFunction(WndProc1, 
            'pointer', ['pointer', 'uint', 'pointer', 'pointer']);
    }

    constructor() {
        const VK_F1 = 0x70;
        const VK_F2 = 0x71;
        const VK_F3 = 0x72;
        const bindinput = new Map([
            [VK_F1, function(){new sunlight().value += 1000;}],
            [VK_F2, function(){for (let index = 0; index < 10; index++) putprop(3, 2, 35); }],
            [VK_F3, rpc.exports.boom],
        ]);

        const thisctx = this;

        Interceptor.replace(thisctx.WndProc, 
            new NativeCallback(function (hWnd, uMsg, wParam, lParam) {
                const WM_KEYDOWN = 0x100;

                if (uMsg == WM_KEYDOWN && bindinput.has(wParam.toInt32())) {
                    bindinput.get(wParam.toInt32())?.();
                }

                return thisctx.WndProc(hWnd, uMsg, wParam, lParam);
            }, 'pointer', ['pointer', 'uint', 'pointer', 'pointer']));
    }
}

new plantsvszombies();