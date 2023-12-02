///<reference path='C:\Users\r0th3r\OneDrive\Code\index.d.ts'/>

function CommunicationDialog(parameter=NULL) 
{
    const GetMessage = new NativeFunction(
        Module.getExportByName('user32.dll', 'GetMessageW'),
        'bool', ['pointer', 'pointer', 'uint32', 'uint32']
    );
    const TranslateMessage = new NativeFunction(
        Module.getExportByName('user32.dll', 'TranslateMessage'),
        'bool', ['pointer']
    );
    const DispatchMessage = new NativeFunction(
        Module.getExportByName('user32.dll', 'DispatchMessageW'),
        'pointer', ['pointer']
    );
    const DefWindowProc = new NativeFunction(
        Module.getExportByName('user32.dll', 'DefWindowProcW'),
        'pointer', ['pointer', 'uint32', 'pointer', 'pointer']
    );
    function MsgOnlyWndProc(hwnd=NULL, message=0, wParam=NULL, lParam=NULL)
    {
        if (message === 0x0001 /* WM_CREATE */) {
            /* TODO */
        }
        if (message === 0x0002 /* WM_DESTROY */) {
            new NativeFunction(
                Module.getExportByName('user32.dll', 'PostQuitMessage'),
                'void', ['int']
            )(0);
        }
    
        if (message === 0x004A /* WM_COPYDATA */) {
            let pcds = ptr(lParam);
            let dwData = Number(pcds.add(Process.pointerSize * 0).readPointer());
            let cbData = pcds.add(Process.pointerSize * 1).readU32();
            let lpData = pcds.add(Process.pointerSize * 2).readPointer();
            // let data = Memory.readByteArray(lpData, cbData);
            let dataJson = lpData.readUtf8String();
            console.log(`ID: ${dwData}\nDATA: ${dataJson}`);
        }
    
        return DefWindowProc(hwnd, message, wParam, lParam);
    } const WindowProcedure = new NativeCallback(MsgOnlyWndProc, 'pointer', ['pointer', 'uint32', 'pointer', 'pointer'])

    const HWND_MESSAGE = ptr(-3);
    let className = Memory.allocUtf16String('Disp32Class');
    let hInstance = Process.enumerateModules()[0].base;

    let lpWndClass = Memory.alloc(8 == Process.pointerSize ? 72 : 40);
    lpWndClass.add(Process.pointerSize).writePointer(WindowProcedure);
    lpWndClass.add(8 == Process.pointerSize ? 24 : 16).writePointer(hInstance);
    lpWndClass.add(8 == Process.pointerSize ? 64 : 36).writePointer(className);

    new NativeFunction(
        Module.getExportByName('user32.dll', 'RegisterClassW'),
        'uint16', ['pointer']
    )(lpWndClass);

    let hWnd = new NativeFunction(
        Module.getExportByName('user32.dll', 'CreateWindowExW'),
        'pointer', ['uint32', 'pointer', 'pointer', 'uint32', 'int', 'int', 'int', 'int', 'pointer', 'pointer', 'pointer', 'pointer']
    )(0, className, Memory.allocUtf16String(`#${Process.id}`), 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, parameter);

    /* Message Loop */
    let bRet = 0; let msg = Memory.alloc(8 == Process.pointerSize ? 48 : 28);
    while ((bRet = GetMessage(msg, NULL, 0, 0)) != 0) {
        if (bRet == -1) break;
        TranslateMessage(msg);
        DispatchMessage(msg);
    }
}

const threadroutine = new NativeCallback(CommunicationDialog, 'void', ['pointer']);
new NativeFunction(
    Module.getExportByName('kernel32.dll', 'CreateThread'),
    'pointer', ['pointer', 'size_t', 'pointer', 'pointer', 'uint32', 'pointer']
)(NULL, 0, threadroutine, NULL, 0, NULL);

/*
    HWND target = FindWindowExW(HWND_MESSAGE, NULL, L"Disp32Class", L"#PID");
    SendMessageW(target, WM_COPYDATA, WPARAM(), LPARAM());
*/