///<reference path='C:/Users/r0th3r/OneDrive/Code/index.d.ts'/>

/**
 * DbgChild (Frida)
 * Usage:
 * uvx --from frida-tools frida -l x64dbg-dbgchild.js -p <target_pid>
 */

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
        const processHandle = pi.readPointer();
        const processId = pi.add(Process.pointerSize * 2).readU32();
        console.log(`    Process created successfully with PID: ${processId}`);

        // Determine child process architecture by reading its PE header
        const pe32 = isProcessPE32(processHandle);
        console.log(`    Architecture: ${pe32 ? 'i386 (PE32)' : 'x64 (PE64)'}`);

        // Launch the matching debugger to catch the newly created suspended process
        rpc.exports.rundbg(rpc.exports.x64dbgdir(), "-pid " + processId, pe32);
    } else {
        const getLastError = new NativeFunction(
            Process.getModuleByName('kernel32.dll').getExportByName('GetLastError'), 'uint32', []);
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


/** 获取当前工作目录(GetCurrentDirectoryW) */
function getCurrentWorkingDirectory() {
    const getCurrentDirectoryW = new NativeFunction(
        Process.getModuleByName('kernel32.dll').getExportByName('GetCurrentDirectoryW'),
        'uint32', ['uint32', 'pointer']
    );
    const buf = Memory.alloc(0x8000); // 32 KiB,足够容纳长路径
    const len = getCurrentDirectoryW(0x8000, buf);
    if (len === 0 || len > 0x8000) return '';
    return buf.readUtf16String();
}

/**
 * 从命令行字符串中解析出第一个 token(即可执行文件完整路径)。
 * 支持带引号("C:\path\app.exe" args)与不带引号(C:\path\app.exe args)两种形式。
 */
function getExePathFromCommandLine() {
    /** 获取当前进程完整命令行(GetCommandLineW) */
    function getCurrentCommandLine() {
        const getCommandLineW = new NativeFunction(
            Process.getModuleByName('kernel32.dll').getExportByName('GetCommandLineW'),
            'pointer', []
        );
        const p = getCommandLineW();
        return p.isNull() ? '' : p.readUtf16String();
    }

    const cmdLine = getCurrentCommandLine();

    if (!cmdLine) return '';
    let i = 0;
    while (i < cmdLine.length && (cmdLine[i] === ' ' || cmdLine[i] === '\t')) i++;
    if (i >= cmdLine.length) return '';

    if (cmdLine[i] === '"') {
        const end = cmdLine.indexOf('"', i + 1);
        return end === -1 ? '' : cmdLine.slice(i + 1, end);
    }

    const end = cmdLine.search(/[ \t]/);
    return end === -1 ? cmdLine.slice(i) : cmdLine.slice(i, end);
}

/** 取路径的父目录(等价于 dirname),结果保留末尾反斜杠 */
function dirname(path) {
    if (!path) return '';
    const trimmed = path.replace(/[\\/]+$/, '');
    const idx = Math.max(trimmed.lastIndexOf('\\'), trimmed.lastIndexOf('/'));
    return idx === -1 ? path : trimmed.slice(0, idx + 1);
}

rpc.exports = {
    x64dbgdir() {
        // default
        return 'C:\\Users\\r0th3r\\Downloads\\Tools\\x64dbg\\release\\';

        //   e.g. "...\release\x64\x64dbg.exe" -> "...\release\x64\" -> "...\release\"
        const exePath = getExePathFromCommandLine();
        if (exePath) {
            const dir = dirname(dirname(exePath));
            if (dir && dir !== exePath) {
                console.log(`[+] x64dbgdir: from command line ("${exePath}") -> ${dir}`);
                return dir;
            }
        }

        //   e.g. "...\release\x64\" -> "...\release\"
        const cwd = getCurrentWorkingDirectory();
        if (cwd) {
            const dir = dirname(cwd);
            if (dir && dir !== cwd) {
                console.log(`[+] x64dbgdir: from current directory -> ${dir}`);
                return dir;
            }
        }
    },
    rundbg(x64dbgdir, commandline, pe32=false) {
        // x64dbgdir 现指向 release 目录
        const exePath = x64dbgdir + (pe32 ? 'x32\\x32dbg.exe' : 'x64\\x64dbg.exe');
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
            const getLastError = new NativeFunction(
                Process.getModuleByName('kernel32.dll').getExportByName('GetLastError'), 'uint32', []);
            console.log(`[-] Failed to launch x64dbg. GetLastError: ${getLastError()}`);
        }
    }
};


/**
 * Determine if a child process is PE32 (i386) by reading its PE header in memory.
 * Uses GetModuleInformation(hProcess, NULL) to get the image base,
 * then ReadProcessMemory to parse DOS → PE → IMAGE_FILE_HEADER.Machine.
 *
 * @param {NativePointer} processHandle - PROCESS_INFORMATION.hProcess
 * @returns {boolean} true if IMAGE_FILE_MACHINE_I386 (0x014c), false otherwise (PE64)
 */
function isProcessPE32(processHandle) {
    const IMAGE_FILE_MACHINE_I386 = 0x014c;

    // GetModuleInformation(processHandle, NULL, &modInfo, sizeof(MODULEINFO))
    const psapi = Process.getModuleByName('psapi.dll');
    const getModuleInformation = new NativeFunction(
        psapi.getExportByName('GetModuleInformation'),
        'bool', ['pointer', 'pointer', 'pointer', 'uint32']
    );

    // MODULEINFO: { LPVOID lpBaseOfDll; DWORD SizeOfImage; LPVOID EntryPoint; }
    const MODULEINFO_SIZE = Process.pointerSize * 2 + 4;
    const modInfo = Memory.alloc(MODULEINFO_SIZE);

    if (!getModuleInformation(processHandle, NULL, modInfo, MODULEINFO_SIZE)) {
        console.log('    [!] GetModuleInformation failed');
        return false;
    }

    const imageBase = modInfo.readPointer();
    console.log(`    Image base: ${imageBase}`);

    // ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
    const readProcessMemory = new NativeFunction(
        Process.getModuleByName('kernel32.dll').getExportByName('ReadProcessMemory'),
        'bool', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']
    );
    const bytesRead = Memory.alloc(Process.pointerSize);

    // 1) Read IMAGE_DOS_HEADER.e_lfanew at offset 0x3C (4 bytes)
    const e_lfanewBuf = Memory.alloc(4);
    if (!readProcessMemory(processHandle, imageBase.add(0x3C), e_lfanewBuf, ptr(4), bytesRead)) {
        console.log('    [!] ReadProcessMemory failed reading e_lfanew');
        return false;
    }
    const e_lfanew = e_lfanewBuf.readU32();

    // 2) Read IMAGE_FILE_HEADER.Machine at PE signature + 4
    //    PE signature "PE\0\0" is 4 bytes, Machine is the next 2 bytes
    const machineBuf = Memory.alloc(2);
    if (!readProcessMemory(processHandle, imageBase.add(e_lfanew + 4), machineBuf, ptr(2), bytesRead)) {
        console.log('    [!] ReadProcessMemory failed reading Machine');
        return false;
    }
    const machine = machineBuf.readU16();
    console.log(`    PE Machine: 0x${machine.toString(16)}`);

    return machine === IMAGE_FILE_MACHINE_I386;
}
