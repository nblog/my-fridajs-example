///<reference path='C:/Users/r0th3r/OneDrive/Code/index.d.ts'/>

/**
 * DbgChild (Frida)
 * Usage:
 * uvx --from frida-tools frida -l x64dbg-dbgchild.js -p <target_pid>
 */


// ============================================================================
// Dispatcher: pick exactly one of the two hook groups above.
// Set HOOK_TARGET to 'ZwCreateUserProcess' or 'CreateProcessInternalW'.
// ============================================================================
const HOOK_TARGET = 'CreateProcessInternalW';

if (HOOK_TARGET === 'ZwCreateUserProcess') {
    installZwCreateUserProcessHook();
} else if (HOOK_TARGET === 'CreateProcessInternalW') {
    installCreateProcessInternalWHook();
} else {
    console.log(`[-] Unknown HOOK_TARGET: ${HOOK_TARGET}. Set it to 'ZwCreateUserProcess' or 'CreateProcessInternalW'.`);
}

const POINTER_SIZE = Process.pointerSize;
// UNICODE_STRING: { USHORT Length; USHORT MaximumLength; PWSTR Buffer; }
// Buffer is pointer-aligned: offset 8 on x64, 4 on x86.
const UNICODE_STRING_BUFFER_OFFSET = (POINTER_SIZE === 8 ? 8 : 4);
const UNICODE_STRING_SIZE = UNICODE_STRING_BUFFER_OFFSET + POINTER_SIZE;

/**
 * A UNICODE_STRING field view with decode helpers.
 * Decoding prefers the in-process ntdll converter
 * RtlUnicodeStringToUTF8String (+ RtlFreeUTF8String to release the
 * allocated UTF8_STRING); when that export is unavailable we fall back
 * to Frida's built-in UTF-16 read.
 */
class UnicodeString {
    /**
     * @param {NativePointer} address pointer to the UNICODE_STRING field
     */
    constructor(address) {
        this.address = address;
        /** @type {number} byte length of the character payload */
        this.length = 0;
        /** @type {NativePointer} */
        this.buffer = NULL;
        if (address.isNull()) return;
        try {
            this.length = address.readU16();
            this.buffer = address.add(UNICODE_STRING_BUFFER_OFFSET).readPointer();
        } catch (e) {
            // Address not readable; getters will report ''.
        }
    }

    /** @returns {boolean} true when there is an actual character payload */
    get hasValue() {
        return this.length !== 0 && !this.buffer.isNull();
    }

    /** @returns {string} decoded text ('' when empty/unreadable) */
    toString() {
        if (!this.hasValue) return '';
        // Prefer the in-process RTL converter; fall back to manual UTF-16 read.
        const viaRtl = UnicodeString._convertWithRtl(this.address);
        if (viaRtl !== null) return viaRtl;
        try {
            return this.buffer.readUtf16String(this.length / 2);
        } catch (e) {
            return `<unreadable: ${e.message}>`;
        }
    }

    /** Decode with Frida's built-in UTF-16 reader, ignoring the RTL path. */
    toStringManual() {
        if (!this.hasValue) return '';
        try {
            return this.buffer.readUtf16String(this.length / 2);
        } catch (e) {
            return `<unreadable: ${e.message}>`;
        }
    }

    /**
     * Decode via ntdll!RtlUnicodeStringToUTF8String. Returns null when the
     * export is unavailable or the conversion fails, so callers can fall
     * back to the manual reader.
     * @param {NativePointer} address
     * @returns {string | null}
     */
    static _convertWithRtl(address) {
        if (!UnicodeString._rtlAvailable) return null;
        // UTF8_STRING: { USHORT Length; USHORT MaximumLength; PCHAR Buffer; }
        const utf8 = Memory.alloc(UNICODE_STRING_SIZE);
        utf8.add(0).writeU16(0);
        utf8.add(2).writeU16(0);
        utf8.add(UNICODE_STRING_BUFFER_OFFSET).writePointer(NULL);
        const status = UnicodeString._rtlConvert(address, utf8);
        let result = null;
        if (status >= 0) { // NT_SUCCESS
            const len = utf8.add(0).readU16();
            const buf = utf8.add(UNICODE_STRING_BUFFER_OFFSET).readPointer();
            if (!buf.isNull()) result = buf.readUtf8String(len);
        }
        UnicodeString._rtlFree(utf8); // release the allocated buffer
        return result;
    }
}

// Resolve ntdll!RtlUnicodeStringToUTF8String / RtlFreeUTF8String once.
// NOTE: these exports only exist on recent ntdll builds; on older systems
// we silently fall back to the manual UTF-16 reader above.
UnicodeString._rtlAvailable = false;
UnicodeString._rtlConvert = null;
UnicodeString._rtlFree = null;
try {
    const ntdll = Process.getModuleByName('ntdll.dll');
    const pConvert = ntdll.getExportByName('RtlUnicodeStringToUTF8String');
    const pFree = ntdll.getExportByName('RtlFreeUTF8String');
    UnicodeString._rtlConvert = new NativeFunction(
        pConvert, 'uint32', ['pointer', 'pointer']);
    UnicodeString._rtlFree = new NativeFunction(
        pFree, 'void', ['pointer']);
    UnicodeString._rtlAvailable = true;
} catch (e) {
    // Leave _rtlAvailable = false -> toString() uses the manual reader.
}

/**
 * PRTL_USER_PROCESS_PARAMETERS view with property getters for the
 * UNICODE_STRING fields we care about. Offsets are architecture-aware.
 */
class RtlUserProcessParameters {
    /**
     * @param {NativePointer} address pointer to RTL_USER_PROCESS_PARAMETERS
     */
    constructor(address) {
        this.address = address;
        let off = 4 * 4;                  // MaximumLength, Length, Flags, DebugFlags
        off += POINTER_SIZE;              // ConsoleHandle
        off += 4;                         // ConsoleFlags
        if (POINTER_SIZE === 8) off += 4; // x64 padding to align next HANDLE
        off += POINTER_SIZE * 3;          // StandardInput, StandardOutput, StandardError
        // CURDIR = { UNICODE_STRING DosPath; HANDLE Handle; }
        const CURDIR_SIZE = UNICODE_STRING_SIZE + POINTER_SIZE;
        this._offCurrentDirectory = off;  // CURDIR.DosPath
        this._offDllPath = off + CURDIR_SIZE;
        this._offImagePath = off + CURDIR_SIZE + UNICODE_STRING_SIZE;
        this._offCommandLine = off + CURDIR_SIZE + UNICODE_STRING_SIZE * 2;
    }

    /** @param {number} offset @returns {UnicodeString} */
    _fieldAt(offset) {
        return new UnicodeString(this.address.add(offset));
    }
    /** @returns {UnicodeString} */
    get imagePath() { return this._fieldAt(this._offImagePath); }
    /** @returns {UnicodeString} */
    get commandLine() { return this._fieldAt(this._offCommandLine); }
    /** @returns {UnicodeString} */
    get currentDirectory() { return this._fieldAt(this._offCurrentDirectory); }
    /** @returns {UnicodeString} */
    get dllPath() { return this._fieldAt(this._offDllPath); }
}

function launchElevatedDebugger(targetPid, pe32 = false) {
    const x64dbgExe = rpc.exports.x64dbgdir() + (pe32 ? 'x32\\x32dbg.exe' : 'x64\\x64dbg.exe');

    // Allocate UTF-16 command line (writable buffer required by CreateProcessInternalW)
    const cmdLineBuf = Memory.allocUtf16String('"' + x64dbgExe + '" ' + `-pid ${targetPid}`);

    // STARTUPINFOW: 104 bytes on x64, 68 bytes on x86 (includes cb field)
    const STARTUPINFOW_SIZE = 8 == Process.pointerSize ? 104 : 68;
    const si = Memory.alloc(STARTUPINFOW_SIZE);
    si.add(0).writeU32(STARTUPINFOW_SIZE); // cb = sizeof(STARTUPINFOW)

    // PROCESS_INFORMATION: 24 bytes on x64 (HANDLE + HANDLE + DWORD + DWORD)
    const PROCESS_INFORMATION_SIZE = 8 == Process.pointerSize ? 24 : 16;
    const pi = Memory.alloc(PROCESS_INFORMATION_SIZE);

    // Launch the process x64dbg
    return new NativeFunction(
        Process.getModuleByName('kernel32.dll').getExportByName('CreateProcessInternalW'),
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
    )(
        NULL,           // hUserToken
        NULL,           // lpApplicationName
        cmdLineBuf,     // lpCommandLine
        NULL,           // lpProcessAttributes
        NULL,           // lpThreadAttributes
        0,              // bInheritHandles
        0,              // dwCreationFlags
        NULL,           // lpEnvironment
        NULL,           // lpCurrentDirectory
        si,             // lpStartupInfo
        pi,             // lpProcessInformation
        NULL            // hRestrictedUserToken
    );
}

function installZwCreateUserProcessHook() {
    const ntdll = Process.getModuleByName('ntdll.dll');
    const zwCreateUserProcess = ntdll.getExportByName('ZwCreateUserProcess');

    const originalZwCreateUserProcess = new NativeFunction(
        zwCreateUserProcess,
        'int', // NTSTATUS (signed; NT_SUCCESS(status) === status >= 0)
        [
            'pointer', // OUT PHANDLE ProcessHandle
            'pointer', // OUT PHANDLE ThreadHandle
            'uint32',  // IN  ACCESS_MASK ProcessDesiredAccess
            'uint32',  // IN  ACCESS_MASK ThreadDesiredAccess
            'pointer', // IN  POBJECT_ATTRIBUTES ProcessObjectAttributes
            'pointer', // IN  POBJECT_ATTRIBUTES ThreadObjectAttributes
            'uint32',  // IN  ULONG ProcessFlags
            'uint32',  // IN  ULONG ThreadFlags
            'pointer', // IN  PRTL_USER_PROCESS_PARAMETERS ProcessParameters
            'pointer', // IN  PPS_CREATE_INFO CreateInfo
            'pointer'  // IN  PPS_ATTRIBUTE_LIST AttributeList
        ]
    );

    Interceptor.replace(zwCreateUserProcess, new NativeCallback(function (
        processHandlePtr,
        threadHandlePtr,
        processDesiredAccess,
        threadDesiredAccess,
        processObjectAttributes,
        threadObjectAttributes,
        processFlags,
        threadFlags,
        processParameters,
        createInfo,
        attributeList
    ) {
        console.log(`[*] ZwCreateUserProcess called:`);
        console.log(`    ProcessFlags: 0x${processFlags.toString(16)}`);
        console.log(`    ThreadFlags: 0x${threadFlags.toString(16)}`);

        // Parse PRTL_USER_PROCESS_PARAMETERS through the class wrapper, and
        // cache the image path for the post-creation architecture check.
        const params = new RtlUserProcessParameters(processParameters);
        const imagePath = params.imagePath.toString();
        const commandLine = params.commandLine.toString();
        const currentDirectory = params.currentDirectory.toString();
        console.log(`    ImagePathName: ${imagePath || 'NULL'}`);
        console.log(`    CommandLine: ${commandLine || 'NULL'}`);
        console.log(`    CurrentDirectory: ${currentDirectory || 'NULL'}`);

        // In the default state, it is suspended.
        const PROCESS_CREATE_FLAGS_CREATE_SUSPENDED = 0x00000200;
        const THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x00000001;

        const status = originalZwCreateUserProcess(
            processHandlePtr,
            threadHandlePtr,
            processDesiredAccess,
            threadDesiredAccess,
            processObjectAttributes,
            threadObjectAttributes,
            processFlags,
            threadFlags,
            processParameters,
            createInfo,
            attributeList
        );

        if (status >= 0) { // NT_SUCCESS(status)
            const processHandle = processHandlePtr.readPointer();
            // GetProcessId(hProcess) -> PID (kernel32)
            const getProcessId = new NativeFunction(
                Process.getModuleByName('kernel32.dll').getExportByName('GetProcessId'),
                'uint32', ['pointer']);
            const processId = getProcessId(processHandle);
            console.log(`    Process created successfully with PID: ${processId}`);

            // Determine child process architecture by reading its PE header
            const pe32 = isProcessPE32FromFile(imagePath);
            console.log(`    Architecture: ${pe32 ? 'i386 (PE32)' : 'x64 (PE64)'}`);

            // Launch the matching debugger to catch the newly created suspended process
            launchElevatedDebugger(processId, pe32);
        } else {
            console.log(`    Failed to create process. NTSTATUS: 0x${(status >>> 0).toString(16)}`);
        }

        return status;
    }, 'int', [
        'pointer',
        'pointer',
        'uint32',
        'uint32',
        'pointer',
        'pointer',
        'uint32',
        'uint32',
        'pointer',
        'pointer',
        'pointer'
    ]));

    console.log(`[+] ZwCreateUserProcess hook installed.`);
}

function installCreateProcessInternalWHook() {
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
        const imagePath = lpApplicationName.isNull() ? 'NULL' : lpApplicationName.readUtf16String();
        const commandLine = lpCommandLine.isNull() ? 'NULL' : lpCommandLine.readUtf16String();
        const currentDirectory = lpCurrentDirectory.isNull() ? 'NULL' : lpCurrentDirectory.readUtf16String();

        console.log(`[*] CreateProcessInternalW called:`);
        console.log(`    lpApplicationName: ${imagePath}`);
        console.log(`    lpCommandLine: ${commandLine}`);
        console.log(`    lpCurrentDirectory: ${currentDirectory}`);
        console.log(`    dwCreationFlags: 0x${dwCreationFlags.toString(16)}`);

        const CREATE_SUSPENDED = 0x00000004;
        if ((dwCreationFlags & CREATE_SUSPENDED) === 0) {
            console.log(`    [+] Applying Suspended flag to the process creation.`);
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
            const processHandle = pi.add(Process.pointerSize * 0).readPointer();
            const threadHandle = pi.add(Process.pointerSize * 1).readPointer();
            const processId = pi.add(Process.pointerSize * 2).readU32();
            const threadId = pi.add(Process.pointerSize * 3).readU32();
            console.log(`    Process created successfully with PID: ${processId}, TID: ${threadId}`);

            // Determine child process architecture by reading its PE header
            const pe32 = isProcessPE32FromFile(imagePath);
            console.log(`    Architecture: ${pe32 ? 'i386 (PE32)' : 'x64 (PE64)'}`);

            // Launch the matching debugger to catch the newly created suspended process
            launchElevatedDebugger(processId, pe32);
        } else {
            console.log(`    Failed to create process.`);
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

    console.log(`[+] CreateProcessInternalW hook installed.`);
}

/**
 * x64dbg 的 release 目录("属性"的存储槽)。
 * rpc.exports 只支持函数导出,不支持属性,因此用
 * get/set 函数对来模拟一个可覆盖的属性:
 *   - rpc.exports.x64dbgdir()      -> getter
 *   - rpc.exports.setx64dbgdir(dir)  -> setter(传 null/'' 恢复默认)
 */
let _x64dbgdir = null;

/** 默认 x64dbg release 目录 */
function defaultX64dbgDir() {
    return Process.getHomeDir() + '\\Downloads\\Tools\\x64dbg\\release\\';
}

rpc.exports = {
    x64dbgdir() {
        return _x64dbgdir || defaultX64dbgDir();
    },
    setx64dbgdir(dir) {
        if (dir === null || dir === undefined || dir === '') {
            _x64dbgdir = null;
            console.log(`[+] x64dbgdir: reset to default (${defaultX64dbgDir()})`);
            return;
        }
        _x64dbgdir = dir;
        console.log(`[+] x64dbgdir: overridden -> ${dir}`);
    },
    rundbg(targetPid, pe32 = false) {

    }
};


const PE32_HEADER_READ_SIZE = 1024;          // file mode: first 1024 bytes

/**
 * Shared PE parser: DOS e_lfanew -> IMAGE_FILE_HEADER.Machine.
 * Expects a NativePointer exposing readU8 / readU16 / readU32 (little-endian
 * by arch), with the readable byte length passed explicitly.
 *
 * @param {NativePointer} buf pointer to the header bytes
 * @param {number} byteLength readable length of the header buffer
 * @returns {boolean} true if IMAGE_FILE_MACHINE_I386
 */
function parsePE32FromBuffer(buf, byteLength) {
    // NativePointer.readXXX(offset) ignores offset — always use add(off).readXXX().
    const readU8 = (off) => buf.add(off).readU8();
    const readU16 = (off) => buf.add(off).readU16();
    const readU32 = (off) => buf.add(off).readU32();

    // e_lfanew lives at 0x3C; verify 'MZ' first
    if (byteLength < 0x40 || readU8(0) !== 0x4D || readU8(1) !== 0x5A) return false; // 'MZ'

    const e_lfanew = readU32(0x3C);
    if (e_lfanew > 4096 || byteLength < e_lfanew + 6) return false;

    // "PE\0\0" sanity check, then Machine (2 bytes following the signature)
    if (readU8(e_lfanew) !== 0x50 || readU8(e_lfanew + 1) !== 0x45 ||
        readU8(e_lfanew + 2) !== 0 || readU8(e_lfanew + 3) !== 0) {
        return false; // not a PE image
    }

    const IMAGE_FILE_MACHINE_I386 = 0x014c;
    return readU16(e_lfanew + 4) === IMAGE_FILE_MACHINE_I386;
}

/**
 * Determine PE32 by reading the first 1024 bytes of the image via Frida File.
 * Uses ArrayBuffer.prototype directly (Frida File.readBytes returns an
 * ArrayBuffer); avoids the buggy writeByteArray path that was scrambling
 * byte order in big reads.
 */
function isProcessPE32FromFile(imagePath) {
    // Binary mode: text mode 'r' would fold CRLF and scramble PE offsets.
    const file = new File(imagePath, 'rb');
    if (!file) return false;
    try {
        const arrayBuffer = /** @type {ArrayBuffer} */ (file.readBytes(PE32_HEADER_READ_SIZE));
        if (!arrayBuffer || arrayBuffer.byteLength === 0) return false;
        const buf = Memory.alloc(arrayBuffer.byteLength);
        buf.writeByteArray(arrayBuffer);
        return parsePE32FromBuffer(buf, arrayBuffer.byteLength);
    } finally {
        file.close();
    }
}

/**
 * Determine PE32 by reading the child process image from memory.
 * Uses GetModuleInformation(hProcess, NULL) for image base, then
 * ReadProcessMemory to pull the DOS header block and reuse the shared parser.
 *
 * @deprecated Unreliable when the child process is suspended at creation before
 * the loader maps its image.
 */
function isProcessPE32FromMemory(processHandle) {
    const k32GetModuleInformation = new NativeFunction(
        Process.getModuleByName('kernel32.dll').getExportByName('K32GetModuleInformation'),
        'bool', ['pointer', 'pointer', 'pointer', 'uint32']
    );

    // MODULEINFO: { LPVOID lpBaseOfDll; DWORD SizeOfImage; LPVOID EntryPoint; }
    const MODULEINFO_SIZE = Process.pointerSize * 2 + 4;
    const modInfo = Memory.alloc(MODULEINFO_SIZE);

    if (!k32GetModuleInformation(processHandle, NULL, modInfo, MODULEINFO_SIZE)) {
        console.log('    [!] K32GetModuleInformation failed');
        return false;
    }

    const imageBase = modInfo.readPointer();
    console.log(`    Image base (memory): ${imageBase}`);

    const readProcessMemory = new NativeFunction(
        Process.getModuleByName('kernel32.dll').getExportByName('ReadProcessMemory'),
        'bool', ['pointer', 'pointer', 'pointer', 'size_t', 'pointer']
    );

    const headerBuf = Memory.alloc(PE32_HEADER_READ_SIZE);
    if (!readProcessMemory(processHandle, imageBase, headerBuf, PE32_HEADER_READ_SIZE, NULL)) {
        console.log('    [!] ReadProcessMemory failed reading header');
        return false;
    }

    return parsePE32FromBuffer(headerBuf, PE32_HEADER_READ_SIZE);
}
