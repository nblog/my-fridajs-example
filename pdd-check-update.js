///<reference path='C:/Users/r0th3r/OneDrive/Code/index.d.ts'/>

/**
 * PDD Workbench - Skip "check update" via ClientFunctionMgr::getFuncEnable hook
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
    skipKeyword: 'func_enable_start_check_update_276',
};

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
const log = function (tag, ...args) {
    const tid = Process.getCurrentThreadId();
    console.log(`[frida][t:${tid}] ${tag}:`, ...args);
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

            if (strValue.includes(CONFIG.skipKeyword)) {
                this.shouldSkip = true;
                log('skip', `Matched "${CONFIG.skipKeyword}" → will force retval=0`);
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
            hookGetFuncEnable();
            log('init', `Hook installed (version=${CONFIG.activeVersion})`);
        } catch (e) {
            log('error', `Init failed: ${e}`);
        }
    }, 100);
});
