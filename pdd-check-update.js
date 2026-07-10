///<reference path='C:/Users/r0th3r/OneDrive/Code/index.d.ts'/>

/**
 * PDD Workbench - Skip "check update" via ClientFunctionMgr::getFuncEnable hook
 *                 + Block PDDUpdate.exe creation via CreateProcessInternalW hook
 *
 * Usage:
 *   uvx --from frida-tools frida --help
 *   uvx --from frida-tools frida -l pdd-check-update.js -f "path\to\PddWorkbench.exe"
 *   # or attach to running process:
 *   uvx --from frida-tools frida -l pdd-check-update.js -n PddWorkbench.exe
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const CONFIG = {
    moduleName: 'PddWorkbench.exe',
    versions: {
        '3.6.0.14': 0x49C3C0,
        '3.6.7.6':  0x4C0FF0,
    },
    activeVersion: '3.6.7.6',
    skipKeywords: [
        'func_enable_start_check_update_276',
        'func_enable_force_auto_update_293',
        'func_enable_silent_update_287',
        'func_enable_main_exec_update_download_294',
        'func_enable_patch_update_349',
        'func_enable_get_leo_update_27517',
        'func_enable_hot_update_check_plugin',
        'func_enable_config_rollback_update_339',
        'enable_func_anti_update_limit_time',
        // 'func_enable_ignore_update_277',
    ],
};

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
const log = function (tag, ...args) {
    const tid = Process.getCurrentThreadId();
    const ts = new Date().toISOString().slice(11, 19); // HH:mm:ss
    console.log(`[frida][${ts}] ${tag}:`, ...args);
};

// ---------------------------------------------------------------------------
// StdString - MSVC std::string reader (SSO-aware)
// ---------------------------------------------------------------------------
/**
 * MSVC std::string layout (x64, 32 bytes total):
 *   +0x00  char[16]  _Buf   (SSO inline buffer)
 *   +0x10  size_t    _Mysize (string length)
 *   +0x18  size_t    _Myres  (reserved capacity)
 *
 * If _Myres <= 15 → SSO: string data is inline at +0x00
 * If _Myres >  15 → heap: +0x00 holds a pointer to the string data
 */
class StdString {
    constructor(ptr) {
        this._ptr = ptr;
    }

    get size() {
        return this._ptr.add(16).readULong();
    }

    get capacity() {
        return this._ptr.add(24).readULong();
    }

    get isSSO() {
        return this.capacity <= 15;
    }

    get dataPtr() {
        if (this.isSSO) {
            return this._ptr;
        }
        return this._ptr.readPointer();
    }

    read() {
        const len = this.size;
        if (len === 0) return '';
        return this.dataPtr.readUtf8String(len) || '';
    }

    toString() {
        return this.read();
    }
}

// ---------------------------------------------------------------------------
// Backtrace helper
// ---------------------------------------------------------------------------
function bt(ctx, limit) {
    limit = limit || 8;
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .slice(0, limit)
        .map(function (addr) {
            const sym = DebugSymbol.fromAddress(addr);
            const mod = Process.findModuleByAddress(addr);
            if (mod) {
                const offset = addr.sub(mod.base);
                return sym.name
                    ? `${mod.name}!${sym.name}+0x${offset.toString(16)}`
                    : `${mod.name}+0x${offset.toString(16)}`;
            }
            return addr.toString();
        });
}

// ---------------------------------------------------------------------------
// Win32 API wrappers (user32.dll)
// ---------------------------------------------------------------------------
const GetWindowTextW = new NativeFunction(
    Process.getModuleByName('user32.dll').getExportByName('GetWindowTextW'),
    'int', ['pointer', 'pointer', 'int']
);

const GetClassNameW = new NativeFunction(
    Process.getModuleByName('user32.dll').getExportByName('GetClassNameW'),
    'int', ['pointer', 'pointer', 'int']
);

const GetParent = new NativeFunction(
    Process.getModuleByName('user32.dll').getExportByName('GetParent'),
    'pointer', ['pointer']
);

const GetWindowRect = new NativeFunction(
    Process.getModuleByName('user32.dll').getExportByName('GetWindowRect'),
    'bool', ['pointer', 'pointer']
);

const DestroyWindow = new NativeFunction(
    Process.getModuleByName('user32.dll').getExportByName('DestroyWindow'),
    'bool', ['pointer']
);

// ---------------------------------------------------------------------------
// WindowInfo - Win32 window information wrapper
// ---------------------------------------------------------------------------
/**
 * Encapsulates window properties: title, class name, parent handle, size.
 * Lazily queries each property on first access.
 */
class WindowInfo {
    constructor(hwnd) {
        this._hwnd = hwnd;
        this._title = null;
        this._className = null;
        this._parent = null;
        this._width = null;
        this._height = null;
    }

    get handle() {
        return this._hwnd;
    }

    get title() {
        if (this._title === null) {
            const buf = Memory.alloc(512 * 2);
            GetWindowTextW(this._hwnd, buf, 512);
            this._title = buf.readUtf16String() || '';
        }
        return this._title;
    }

    get className() {
        if (this._className === null) {
            const buf = Memory.alloc(256 * 2);
            GetClassNameW(this._hwnd, buf, 256);
            this._className = buf.readUtf16String() || '';
        }
        return this._className;
    }

    get parent() {
        if (this._parent === null) {
            this._parent = GetParent(this._hwnd);
        }
        return this._parent;
    }

    get width() {
        if (this._width === null) {
            this._queryRect();
        }
        return this._width;
    }

    get height() {
        if (this._height === null) {
            this._queryRect();
        }
        return this._height;
    }

    _queryRect() {
        const rect = Memory.alloc(16); // RECT: left(4), top(4), right(4), bottom(4)
        GetWindowRect(this._hwnd, rect);
        const left   = rect.readS32();
        const top    = rect.add(4).readS32();
        const right  = rect.add(8).readS32();
        const bottom = rect.add(12).readS32();
        this._width  = right - left;
        this._height = bottom - top;
    }

    toString() {
        return `WindowInfo(hwnd=0x${this._hwnd.toString(16)}, `
            + `title="${this.title}", `
            + `class="${this.className}", `
            + `parent=0x${this.parent.toString(16)}, `
            + `size=${this.width}x${this.height})`;
    }
}

// ---------------------------------------------------------------------------
// Hook: CreateWindowExW
// ---------------------------------------------------------------------------
function hookCreateWindowExW() {
    const createWindowExW = Process.getModuleByName('user32.dll').getExportByName('CreateWindowExW');

    function isHex32(str) {
        return str.length === 32 && /^[0-9a-z]{32}$/.test(str);
    }

    Interceptor.attach(createWindowExW, {
        onEnter(args) {
            // Save parameters for onLeave inspection
            this.lpClassName = args[1];
            this.lpWindowName = args[2];
        },
        onLeave(retval) {
            const hWnd = retval;
            if (hWnd.isNull()) return; // creation failed, nothing to do

            try {
                const wi = new WindowInfo(hWnd);

                // Check if the window matches the criteria: title and class name are 32-character hex strings, and size is 476x468
                if (isHex32(wi.title) && isHex32(wi.className) &&
                    wi.width === 476 && wi.height === 468) {
                    log('destroy', `CreateWindowExW → destroying matched window: ${wi}`);
                    DestroyWindow(hWnd);
                }
            } catch (e) {
                // Silently ignore — don't break normal window creation
            }
        }
    });

    log('hook', 'CreateWindowExW hook installed (destroying 476x468 hex-titled windows after creation)');
}

// ---------------------------------------------------------------------------
// Hook: CreateProcessInternalW
// ---------------------------------------------------------------------------
function hookCreateProcess() {
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
        const appName = lpApplicationName.isNull() ? '' : lpApplicationName.readUtf16String();
        const cmdLine = lpCommandLine.isNull() ? '' : lpCommandLine.readUtf16String();

        const target = appName || cmdLine;

        /*
        // Log pddwebworkbench.exe command line and inject remote debugging parameters
        if (target.toLowerCase().includes('pddwebworkbench.exe')) {
            log('observe', `CreateProcessInternalW → PddWebWorkbench detected`);
            log('observe', `  lpApplicationName: ${appName || 'NULL'}`);
            log('observe', `  lpCommandLine: ${cmdLine || 'NULL'}`);
            
            // Append remote debugging parameters for CDP
            const newCmdLine = cmdLine + ' --remote-debugging-port=9222 --remote-allow-origins=*';
            const newCmdLinePtr = Memory.allocUtf16String(newCmdLine);
            log('observe', `  Modified lpCommandLine: ${newCmdLine}`);
            
            // Call original with modified command line
            return originalCreateProcessInternalW(
                hUserToken,
                lpApplicationName,
                newCmdLinePtr,
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
        }
        */

        // Check if the target is PDDUpdate.exe or FullUpdate_<version>_.exe
        const isPddUpdate = target.toLowerCase().includes('pddupdate.exe');
        const isFullUpdate = /FullUpdate_[\d.]+_\.exe/i.test(target);
        if (isPddUpdate || isFullUpdate) {
            log('block', `CreateProcessInternalW blocked: ${isPddUpdate ? 'PDDUpdate' : 'FullUpdate'} detected`);
            log('block', `  lpApplicationName: ${appName || 'NULL'}`);
            log('block', `  lpCommandLine: ${cmdLine || 'NULL'}`);
            return 1; // return TRUE (success) without actually creating the process
        }

        return originalCreateProcessInternalW(
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

    log('hook', 'CreateProcessInternalW hook installed (blocking PDDUpdate.exe)');
}

// ---------------------------------------------------------------------------
// Hook: ClientFunctionMgr::getFuncEnable
// ---------------------------------------------------------------------------
function hookGetFuncEnable() {
    const mod = Process.getModuleByName(CONFIG.moduleName);
    const offset = CONFIG.versions[CONFIG.activeVersion];
    if (!offset) {
        log('error', `Unknown version: ${CONFIG.activeVersion}`);
        return;
    }

    const targetAddr = mod.base.add(offset);
    log('hook', `ClientFunctionMgr::getFuncEnable @ ${targetAddr} (${CONFIG.moduleName}+0x${offset.toString(16)})`);

    Interceptor.attach(targetAddr, {
        onEnter(args) {
            // args[1] is the second parameter — likely a std::string*
            const stdStr = new StdString(args[1]);
            const strValue = stdStr.read();

            this.shouldSkip = false;
            this.strValue = strValue;

            // log('enter', 'getFuncEnable',
            //     `arg1="${strValue}"`,
            //     // `size=${stdStr.size}`,
            //     // `sso=${stdStr.isSSO}`,
            //     `caller=${DebugSymbol.fromAddress(this.returnAddress)}`);

            // // Dump raw memory of arg1 for debugging
            // log('dump', 'arg1 raw', '\n' + hexdump(args[1], { length: 32, ansi: true }));

            const matched = CONFIG.skipKeywords.find(function (kw) { return strValue.includes(kw); });
            if (matched) {
                this.shouldSkip = true;
                log('skip', `Matched "${matched}" → will force retval=0`);
            }
        },
        onLeave(retval) {
            if (this.shouldSkip) {
                const original = retval.toInt32();
                retval.replace(0);
                log('patched', 'getFuncEnable',
                    `original=${original} → forced=0`,
                    `key="${this.strValue}"`);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Entry point — delayed to let VMP finish its init
// ---------------------------------------------------------------------------
new Promise(function () {
    setTimeout(function () {
        try {
            (function () {
                const ntdll = Process.getModuleByName('ntdll.dll');
                const addr = ntdll.getExportByName('NtProtectVirtualMemory');

                if (addr.readU8() === 0xe9) {
                    Memory.patchCode(addr, 64, function (code) {
                        const cw = new X86Writer(code, { pc: addr });
                        if (Process.pointerSize === 8) {
                            cw.putMovRegReg('r10', 'rcx');
                        }
                        cw.putMovRegU32('eax', 0x50); // NtProtectVirtualMemory syscall number
                        cw.flush();
                    });
                    log('vmp-bypass', 'Patched NtProtectVirtualMemory');
                } else {
                    log('vmp-bypass', 'NtProtectVirtualMemory not hooked (no JMP stub), skipping patch');
                }
            })();
            hookCreateWindowExW();
            hookCreateProcess();
            hookGetFuncEnable();
            log('init', `Hooks installed (version=${CONFIG.activeVersion})`);
        } catch (e) {
            log('error', `Init failed: ${e}`);
        }
    }, 100);
});
