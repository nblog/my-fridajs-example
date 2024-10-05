///<reference path='C:\Users\r0th3r\OneDrive\Code\index.d.ts'/>


/* https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-closehandle */
const CloseHandle = new NativeFunction(
    Module.getExportByName('kernel32.dll', 'CloseHandle'),
    'bool', ['pointer']);

/* https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-readfile */
const ReadFile = new NativeFunction(
    Module.getExportByName('kernel32.dll', 'ReadFile'),
    'bool', ['pointer', 'pointer', 'uint32', 'pointer', 'pointer']);

/* https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-writefile */
const WriteFile = new NativeFunction(
    Module.getExportByName('kernel32.dll', 'WriteFile'),
    'bool', ['pointer', 'pointer', 'uint32', 'pointer', 'pointer']);

/* https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfile2 */
const CreateFile2 = new NativeFunction(
    Module.getExportByName('kernel32.dll', 'CreateFile2'),
    'pointer', ['pointer', 'uint32', 'uint32', 'uint32', 'pointer']);

/* https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilea */
const CreateFileA = new NativeFunction(
    Module.getExportByName('kernel32.dll', 'CreateFileA'),
    'pointer', ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'pointer']);

/* https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew */
const CreateFileW = new NativeFunction(
    Module.getExportByName('kernel32.dll', 'CreateFileW'), 
    'pointer', ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'pointer']);

const CreateFile = CreateFileW;


/*
const ATTACH_PARENT_PROCESS = -1;
new NativeFunction(
    Module.getExportByName('kernel32.dll', 'AttachConsole'),
    'bool', ['uint32'])(ATTACH_PARENT_PROCESS);
*/
new NativeFunction(
    Module.getExportByName('kernel32.dll', 'AllocConsole'),
    'bool', [])();
new NativeFunction(
    Module.getExportByName('kernel32.dll', 'SetConsoleTitleA'),
    'bool', ['pointer'])(Memory.allocUtf8String('Debug Console'));

/*
const stdin = new NativeFunction(
    Module.getExportByName('msvcrt.dll', '__iob_func'),
    'pointer', ['int'])(0);
const stdout = new NativeFunction(
    Module.getExportByName('msvcrt.dll', '__iob_func'),
    'pointer', ['int'])(1);
const stderr = new NativeFunction(
    Module.getExportByName('msvcrt.dll', '__iob_func'),
    'pointer', ['int'])(2);
*/
const stdin = new NativeFunction(
    Module.getExportByName('ucrtbase.dll', '__acrt_iob_func'), 
    'pointer', ['int'])(0);
const stdout = new NativeFunction(
    Module.getExportByName('ucrtbase.dll', '__acrt_iob_func'), 
    'pointer', ['int'])(1);
const stderr = new NativeFunction(
    Module.getExportByName('ucrtbase.dll', '__acrt_iob_func'), 
    'pointer', ['int'])(2);

/*
new NativeFunction(
    Module.getExportByName('msvcrt.dll', 'freopen'),
    'pointer', ['pointer', 'pointer', 'pointer'])
    (Memory.allocUtf8String('CONOUT$'), Memory.allocUtf8String('w'), stdout);
*/
new NativeFunction(
    Module.getExportByName('ucrtbase.dll', 'freopen'),
    'pointer', ['pointer', 'pointer', 'pointer'])
    (Memory.allocUtf8String('CONOUT$'), Memory.allocUtf8String('w'), stdout);
/*
new NativeFunction(
    Module.getExportByName('ucrtbase.dll', 'freopen'),
    'pointer', ['pointer', 'pointer', 'pointer'])
    (Memory.allocUtf8String('CONERR$'), Memory.allocUtf8String('w'), stderr);
new NativeFunction(
    Module.getExportByName('ucrtbase.dll', 'freopen'),
    'pointer', ['pointer', 'pointer', 'pointer'])
    (Memory.allocUtf8String('CONIN$'), Memory.allocUtf8String('r'), stdin);
*/



/* https://learn.microsoft.com/windows/win32/inputdev/virtual-key-codes */
function KeyState(vkcode, ctrl=false, alt=false, shift=false) {
    const GetAsyncKeyState = new NativeFunction(
        Module.getExportByName('user32.dll', 'GetAsyncKeyState'),
        'int', ['int']);

    const CHECK = 0x8000;

    let vkcodePressed = (GetAsyncKeyState(vkcode) & CHECK) != 0;

    let ctrlPressed = (GetAsyncKeyState(0x11/*VK_CONTROL*/) & CHECK) != 0;
    let altPressed = (GetAsyncKeyState(0x12/*VK_MENU*/) & CHECK) != 0;
    let shiftPressed = (GetAsyncKeyState(0x10/*VK_SHIFT*/) & CHECK) != 0;

    return vkcodePressed &&
    (ctrl == ctrlPressed) && 
    (alt == altPressed) &&
    (shift == shiftPressed);
}

const timerId = setInterval(() => {
    if (KeyState(0xC0/*VK_OEM_3*/, true)) {
        console.log('Esc');
        clearInterval(timerId);
    }

    if (KeyState(0x70/*VK_F1*/)) {
        console.log('F1');
    }
    if (KeyState(0x71/*VK_F2*/)) {
        console.log('F2');
    }
}, 0.3 * 1000);