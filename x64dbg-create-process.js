///<reference path='C:/Users/r0th3r/OneDrive/Code/index.d.ts'/>

const kernel32 = Process.getModuleByName('kernelbase.dll');
const createProcessInternalW = kernel32.getExportByName('CreateProcessInternalW');

const originalCreateProcessInternalW = new NativeFunction(
    createProcessInternalW,
    'bool',
    [
        'pointer',  // IN  HANDLE hUserToken
        'pointer',  // IN  LPCWSTR lpApplicationName
        'pointer',  // IN  LPWSTR lpCommandLine
        'pointer',  // IN  LPSECURITY_ATTRIBUTES lpProcessAttributes
        'pointer',  // IN  LPSECURITY_ATTRIBUTES lpThreadAttributes
        'bool',     // IN  BOOL bInheritHandles
        'uint32',   // IN  DWORD dwCreationFlags
        'pointer',  // IN  LPVOID lpEnvironment
        'pointer',  // IN  LPCWSTR lpCurrentDirectory
        'pointer',  // IN  LPSTARTUPINFOW lpStartupInfo
        'pointer',  // IN  LPPROCESS_INFORMATION lpProcessInformation
        'pointer'   // OUT PHANDLE hRestrictedUserToken
    ]
);


Interceptor.replace(createProcessInternalW, new NativeCallback(function (
    hUserToken,
    lpApplicationName,
    lpCommandLine,
    lpProcessAttributes,
    lpThreadAttributes,
    bInheritHandles,
    dwCreationFlags,
    lpEnvironment,
    lpCurrentDirectory,
    lpStartupInfo,
    lpProcessInformation,
    hRestrictedUserToken
) {
    const appName = lpApplicationName.isNull() ? 'NULL' : lpApplicationName.readUtf16String();
    const cmdLine = lpCommandLine.isNull() ? 'NULL' : lpCommandLine.readUtf16String();
    const dirName = lpCurrentDirectory.isNull() ? 'NULL' : lpCurrentDirectory.readUtf16String();

    console.log(`[*] CreateProcessInternalW called:`);
    console.log(`    lpApplicationName: ${appName}`);
    console.log(`    lpCommandLine: ${cmdLine}`);
    console.log(`    lpCurrentDirectory: ${dirName}`);
    console.log(`    dwCreationFlags: 0x${dwCreationFlags.toString(16)}`);

    const CREATE_SUSPENDED = 0x00000004;
    if ((dwCreationFlags & CREATE_SUSPENDED) === 0) {
        console.log(`    Warning: Process is not created in a suspended state. Consider using CREATE_SUSPENDED for better analysis.`);
        dwCreationFlags |= CREATE_SUSPENDED;
    }

    const result = originalCreateProcessInternalW(
        hUserToken,
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        hRestrictedUserToken
    );

    if (result) {
        // https://learn.microsoft.com/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
        const pi = lpProcessInformation;
        const processId = pi.add(Process.pointerSize * 2).readU32();
        console.log(`    Process created successfully with PID: ${processId}`);
        
        // Launch x64dbg to catch the newly created process in a suspended state
        rpc.exports.rundbg(rpc.exports.x64dbgdir(), "-pid " + processId);
    } else {
        const getLastError = new NativeFunction(kernel32.getExportByName('GetLastError'), 'uint32', []);
        const errorCode = getLastError();
        console.log(`    Failed to create process. GetLastError: ${errorCode}`);
    }

    return result;
}, 'bool', [
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'bool',
    'uint32',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer'
]));


rpc.exports = {
    x64dbgdir() {
        return 'C:\\Users\\r0th3r\\Downloads\\Tools\\x64dbg\\release\\x64\\';
    },
    rundbg(x64dbgdir, commandline) {
        const exePath = x64dbgdir + 'x64dbg.exe';
        console.log(`[*] rundbg: launching ${exePath}`);

        // Allocate UTF-16 command line (writable buffer required by CreateProcessInternalW)
        const cmdLineBuf = Memory.allocUtf16String('"' + exePath + '" ' + (commandline || ''));

        // STARTUPINFOW: 104 bytes on x64, 68 bytes on x86 (includes cb field)
        const STARTUPINFOW_SIZE = 8 == Process.pointerSize ? 104 : 68;
        const si = Memory.alloc(STARTUPINFOW_SIZE);
        si.add(0).writeU32(STARTUPINFOW_SIZE); // cb = sizeof(STARTUPINFOW)

        // PROCESS_INFORMATION: 24 bytes on x64 (HANDLE + HANDLE + DWORD + DWORD)
        const PROCESS_INFORMATION_SIZE = 8 == Process.pointerSize ? 24 : 16;
        const pi = Memory.alloc(PROCESS_INFORMATION_SIZE);

        // Current directory as UTF-16
        const curDir = Memory.allocUtf16String(x64dbgdir);

        const result = originalCreateProcessInternalW(
            NULL,           // hUserToken
            NULL,           // lpApplicationName
            cmdLineBuf,     // lpCommandLine
            NULL,           // lpProcessAttributes
            NULL,           // lpThreadAttributes
            0,              // bInheritHandles
            0,              // dwCreationFlags
            NULL,           // lpEnvironment
            curDir,         // lpCurrentDirectory
            si,             // lpStartupInfo
            pi,             // lpProcessInformation
            NULL            // hRestrictedUserToken
        );

        if (result) {
            console.log(`[+] x64dbg launched successfully!`);
        } else {
            const getLastError = new NativeFunction(kernel32.getExportByName('GetLastError'), 'uint32', []);
            console.log(`[-] Failed to launch x64dbg. GetLastError: ${getLastError()}`);
        }
    }
};