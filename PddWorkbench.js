///<reference path='C:/Users/r0th3r/OneDrive/Code/index.d.ts'/>

/**
 * PDD Workbench - Skip "check update" via
 *                 + Block PDDUpdate.exe creation via CreateProcessInternalW hook
 *
 * Usage:
 *   uvx --from frida-tools frida --help
 *   uvx --from frida-tools frida -l PddWorkbench.js -f "path\to\PddWorkbench.exe"
 *   # or attach to running process:
 *   uvx --from frida-tools frida -l PddWorkbench.js -n PddWorkbench.exe
 *
 * Attach mode notes:
 *   PDDProtect.dll hooks LdrLoadDll to detect and block frida-agent.dll.
 *   When attaching (not spawning), we must patch LdrLoadDll early to bypass
 *   this anti-frida check before the agent DLL is loaded.
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const CONFIG = {
    moduleName: 'PddWorkbench.exe',
    activeVersion: '3.6.7.6',
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
// StdTree - MSVC std::_Tree (std::map / std::set) node reader & traversal
// ---------------------------------------------------------------------------
/**
 * MSVC _Tree_node layout (x64):
 *   +0x00  _Left    (head: leftmost node  / node: left child)
 *   +0x08  _Parent  (head: root node      / node: parent)
 *   +0x10  _Right   (head: rightmost node / node: right child)
 *   +0x18  _Color   (0 = red, 1 = black)
 *   +0x19  _Isnil   (1 = sentinel head node, 0 = real node)
 *   +0x20  _Myval   (set<T>: T;  map<K,V>: pair<const K, V>)
 *
 * The sentinel head node (_Isnil == 1) is allocated by the std::_Tree object.
 * For a non-empty tree its _Left/_Parent/_Right point at the first/root/last
 * real nodes; for an empty tree all three point back at the head itself.
 */
class StdTreeNode {
    constructor(ptr) {
        this._ptr = ptr;
    }

    get left() {
        return this._ptr.readPointer();
    }

    get parent() {
        return this._ptr.add(8).readPointer();
    }

    get right() {
        return this._ptr.add(16).readPointer();
    }

    /** 0 = red, 1 = black */
    get color() {
        return this._ptr.add(24).readU8();
    }

    get colorName() {
        return this.color === 0 ? 'red' : 'black';
    }

    /** true for the sentinel head node (not a real element) */
    get isNil() {
        return this._ptr.add(25).readU8() !== 0;
    }

    /**
     * Pointer to the stored value (_Myval at +0x20).
     * Interpretation depends on the container's value_type:
     *   set<T>    → T
     *   map<K,V>  → pair<const K, V>  (K at +0x00, V after K, aligned)
     */
    data() {
        return this._ptr.add(32);
    }

    toString() {
        const tag = this.isNil ? 'head' : this.colorName;
        return `StdTreeNode(${this._ptr}, ${tag})`;
    }
}

/**
 * In-order (sorted) traversal over a MSVC std::_Tree.
 * Construct with the sentinel head node address, or use fromTreeObject()
 * with the std::map/std::set object address.
 */
class StdTree {
    /** @param {NativePointer} headPtr - address of the _Isnil==1 head node */
    constructor(headPtr) {
        this._head = new StdTreeNode(headPtr);
    }

    /**
     * Build from the std::_Tree (std::map/std::set) object itself.
     * MSVC x64 object layout: +0x00 = _Myhead, +0x08 = _Mysize.
     * @param {NativePointer} treePtr
     */
    static fromTreeObject(treePtr) {
        return new StdTree(treePtr.readPointer());
    }

    get head() {
        return this._head;
    }

    get isEmpty() {
        return this._head.left.equals(this._head._ptr);
    }

    /** First (minimum) node pointer; equals head when the tree is empty */
    get first() {
        return this._head.left;
    }

    /** Last (maximum) node pointer; equals head when the tree is empty */
    get last() {
        return this._head.right;
    }

    /** Root node pointer; equals head when the tree is empty */
    get root() {
        return this._head.parent;
    }

    /**
     * All real nodes in sorted order. Aborts early on corrupt pointers
     * or when maxNodes is exceeded, returning whatever was collected.
     * @param {number} [maxNodes=100000] safety cap
     * @returns {StdTreeNode[]}
     */
    nodes(maxNodes) {
        maxNodes = maxNodes || 100000;
        const out = [];
        try {
            let node = new StdTreeNode(this.first);
            while (!node.isNil && out.length < maxNodes) {
                out.push(node);
                // in-order successor
                const right = new StdTreeNode(node.right);
                if (!right.isNil) {
                    node = right;
                    let next = new StdTreeNode(node.left);
                    while (!next.isNil) {
                        node = next;
                        next = new StdTreeNode(node.left);
                    }
                } else {
                    let parent = new StdTreeNode(node.parent);
                    while (!parent.isNil && node._ptr.equals(parent.right)) {
                        node = parent;
                        parent = new StdTreeNode(parent.parent);
                    }
                    node = parent;
                }
            }
        } catch (e) {
            log('stdtree', `walk aborted after ${out.length} nodes: ${e.message}`);
        }
        if (out.length >= maxNodes) {
            log('stdtree', `walk hit maxNodes cap (${maxNodes}) - tree may be corrupt`);
        }
        return out;
    }

    /**
     * Value pointers (_Myval) of all nodes, in sorted order.
     * @param {function(StdTreeNode): *} [read] optional per-node reader;
     *        defaults to returning the raw data() pointer
     * @returns {Array}
     */
    values(read) {
        read = read || function (node) { return node.data(); };
        return this.nodes().map(function (node) { return read(node); });
    }

    /**
     * Log one line per node with structure info.
     * @param {function(StdTreeNode): string} [read] optional value formatter
     */
    dump(read) {
        const nodes = this.nodes();
        log('stdtree', `head=${this._head._ptr} empty=${this.isEmpty} count=${nodes.length}`);
        nodes.forEach(function (node, i) {
            let extra = '';
            if (read) {
                try {
                    extra = ' value=' + read(node);
                } catch (e) {
                    extra = ` value=<read error: ${e.message}>`;
                }
            }
            log('stdtree', `#${i} ${node.colorName} node=${node._ptr}` +
                ` left=${node.left} parent=${node.parent} right=${node.right}` +
                ` data=${node.data()}${extra}`);
        });
    }
}

// ---------------------------------------------------------------------------
// Helper: wait for a module to be loaded, then run a callback with it
// ---------------------------------------------------------------------------
/**
 * Some DLLs (e.g. pddconfig.dll) are loaded lazily after process start, so
 * looking them up during the initial hook pass can fail with "unable to
 * find module". Poll until the module appears (or give up after a while).
 * @param {string} name module file name, e.g. 'pddconfig.dll'
 * @param {function(Module): void} callback invoked once the module is found
 * @param {number} [intervalMs=200] poll interval
 * @param {number} [maxAttempts=50] give up after this many polls
 */
function waitForModule(name, callback, intervalMs, maxAttempts) {
    intervalMs = intervalMs || 200;
    maxAttempts = maxAttempts || 50;

    let attempts = 0;
    const timer = setInterval(function () {
        const mod = Process.findModuleByName(name);
        if (mod) {
            clearInterval(timer);
            log('wait-module', `Module '${name}' loaded after ${attempts} attempt(s)`);
            callback(mod);
            return;
        }

        attempts++;
        if (attempts >= maxAttempts) {
            clearInterval(timer);
            log('wait-module', `Timed out waiting for module '${name}' after ${attempts} attempts`);
        }
    }, intervalMs);
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
            } catch (e) {
                // Silently ignore — don't break normal window creation
            }
        }
    });

    log('hook', 'CreateWindowExW hook installed (destroying windows after creation)');
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
// Hook: ConfigCenter::GetItem (pddconfig.dll)
// ---------------------------------------------------------------------------
/** @param {Module} mod resolved pddconfig.dll module */
function hookConfigGetItem(mod) {
    // pddconfig.dll — resolved by mangled export name
    const targets = [
        {
            name: 'GetItem<string>', kind: 'string',
            addr: mod.getExportByName('??$GetItem@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@ConfigCenter@@QEBA_NV?$basic_string_view@DU?$char_traits@D@std@@@std@@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@1AEAV32@@Z'),
        },
        {
            name: 'GetItem<bool>', kind: 'bool',
            addr: mod.getExportByName('??$GetItem@_N@ConfigCenter@@QEBA_NV?$basic_string_view@DU?$char_traits@D@std@@@std@@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@1AEA_N@Z'),
        },
        {
            name: 'GetItem<long>', kind: 'long',
            addr: mod.getExportByName('??$GetItem@J@ConfigCenter@@QEBA_NV?$basic_string_view@DU?$char_traits@D@std@@@std@@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@1AEAJ@Z'),
        },
        {
            name: 'GetItem<double>', kind: 'double',
            addr: mod.getExportByName('??$GetItem@N@ConfigCenter@@QEBA_NV?$basic_string_view@DU?$char_traits@D@std@@@std@@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@1AEAN@Z'),
        },
    ];

    const skipKeywords = [
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
        // 'func_detect_debugger_275',
    ];

    targets.forEach(function (t) {
        Interceptor.attach(t.addr, {
            onEnter(args) {
                this.shouldSkip = false;
                this.kind = t.kind;
                this.outPtr = args[4];

                let key = '';
                try {
                    key = new StdString(args[3]).read();
                } catch (e) { }
                this.key = key;

                const matched = skipKeywords.find(function (kw) { return key.includes(kw); });
                if (matched) {
                    this.shouldSkip = true;
                    this.matched = matched;
                    log('skip2', `${t.name} matched "${matched}"`);
                }
            },
            onLeave(retval) {
                if (!this.shouldSkip) {
                    return;
                }

                try {
                    let original;
                    if (this.kind === 'string') {
                        original = new StdString(this.outPtr).read();
                    }
                    if (this.kind === 'bool') {
                        original = this.outPtr.readU8();
                        this.outPtr.writeU8(0);
                    } else if (this.kind === 'long') {
                        original = this.outPtr.readS32();
                        this.outPtr.writeS32(0);

                    } else if (this.kind === 'double') {
                        original = this.outPtr.readDouble();
                        this.outPtr.writeDouble(0);
                    }

                    retval.replace(1);
                    log('patched2', `${t.name} out-param original=${original} -> forced=0 key="${this.key}"`);
                } catch (e) {
                    log('skip2', `${t.name} clear out-param failed: ${e}`);
                }
            }
        });
    });

    log('hook', `ConfigCenter::GetItem hooks installed (${targets.length} targets)`);
}

// ---------------------------------------------------------------------------
// Hook: IUserCenter select-user (店铺/联系人切换) vfunc
// ---------------------------------------------------------------------------
/**
 * IUserCenter::vtbl[0x490 / 8 = 146th virtual function] fires when the
 * active contact/mall (联系人) selection changes.
 */
function hookSelectUser() {
    const instance = new NativeFunction(
        Process.getModuleByName('pddworkbenchdata.dll').getExportByName('?GetInstance@IUserCenter@@SAPEAV1@XZ'),
        'pointer',
        []
    )();

    // C++ object layout: [0x0] = vtable pointer
    const vtbl = instance.readPointer();
    const target = vtbl.add(0x490).readPointer(); // 146th virtual function

    Interceptor.attach(target, {
        onEnter(args) {
            try {
                const mallcsid = new StdString(args[1]).read();
                const userId = new StdString(args[2]).read();

                log('select-user', `switch to mallcsid="${mallcsid}" userId="${userId}"`);
            } catch (e) { }
        }
    });

    log('hook', `select user switch hook installed: instance=${instance} vtbl=${vtbl} target=${target}`);
}

// ---------------------------------------------------------------------------
// Hook: workbenchdb.dll insert
// ---------------------------------------------------------------------------
/**
 *   arg2 = mallcsid        — MSVC std::string
 *   arg3 = message         — struct pointer
 *   message + 0xC8         — std::string (message content)
 */
function hookDbInsert() {
    const mod = Process.getModuleByName('workbenchdb.dll');
    // 3.6.7.6:  0x82B0
    const targetAddr = mod.base.add(0x82B0);

    Interceptor.attach(targetAddr, {
        onEnter(args) {
            try {
                const mallcsid = new StdString(args[1]).read();
                const message = new StdString(args[2].add(0xC8)).read();

                log('db-insert', `mallcsid="${mallcsid}"`);
                log('db-insert', `message="${JSON.stringify(message)}"`);
            } catch (e) {
                log('db-insert', `Failed to read args: ${e}`);
            }
        },
        onLeave(retval) {}
    });

    log('hook', 'workbenchdb.dll insert hook installed (+0x82B0)');
}

// ---------------------------------------------------------------------------
// Hook: MallCSID
// ---------------------------------------------------------------------------
function hookMallCSID() {
    const mod = Process.mainModule;
    // 3.6.7.6:  0x1DD6B9
    const targetAddr = mod.base.add(0x1DD6B9);

    Interceptor.attach(targetAddr, {
        onEnter(args) {
            try {
                const stdStr = new StdString((this.context).rax);
                const value = stdStr.read();
                if (value) {
                    log('mallcsid', `MallCSID = "${value}"`);
                }
            } catch (e) {
                log('mallcsid', `Failed to read std::string at ${strPtr}: ${e}`);
            }
        },
        onLeave(retval) {}
    });
}

// ---------------------------------------------------------------------------
// Patch: LdrLoadDll (anti-frida bypass for attach mode)
// ---------------------------------------------------------------------------
/**
 * PDDProtect.dll hooks ntdll!LdrLoadDll to inspect DLL names being loaded
 * and blocks frida-agent.dll (and related Frida runtime DLLs).
 *
 * When spawning (-f), Frida injects before PDDProtect initializes, so this
 * is not an issue. But when attaching (-n / -p), PDDProtect is already
 * active and will reject the agent DLL load.
 *
 * Strategy: Hook LdrLoadDll and filter out the anti-frida check so that
 * frida-agent.dll can be loaded without being blocked.
 */
function hookLdrLoadDll() {
    // TODO: implement LdrLoadDll patch for attach mode
    //   1. Get ntdll!LdrLoadDll address
    //   2. Interceptor.attach onEnter: read DllPath / DllName (UNICODE_STRING)
    //   3. If the DLL name matches frida-agent*.dll, skip PDDProtect's filter
    //   4. Alternatively: replace LdrLoadDll with a trampoline that calls
    //      the original ntdll implementation directly, bypassing the hook
    log('patch', 'LdrLoadDll patch placeholder (attach mode anti-frida bypass)');
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
            hookLdrLoadDll();
            hookCreateWindowExW();
            hookCreateProcess();
            waitForModule('pddconfig.dll', hookConfigGetItem);
            // hookSelectUser();
            // hookDbInsert();
            log('init', `Hooks installed (version=${CONFIG.activeVersion})`);
        } catch (e) {
            log('error', `Init failed: ${e}`);
        }
    }, 100);
});

rpc.exports = {
    getpassids: function () {
        const instance = new NativeFunction(
            Process.getModuleByName("pddworkbenchdata.dll").getExportByName("?GetInstance@IUserCenter@@SAPEAV1@XZ"),
            'pointer',
            []
        )();
        const tree = new StdTree(instance.add(0x10).readPointer());
        return tree.values(n => new StdString(n.data().add(0x20)).read());
    },
    getcurrentmallid: function () {
        const instance = new NativeFunction(
            Process.getModuleByName("pddworkbenchdata.dll").getExportByName("?GetInstance@IUserCenter@@SAPEAV1@XZ"),
            'pointer',
            []
        )();
        return new StdString(instance.add(0x398)).read();
    },
    getmallnicknames: function () {
        const instance = new NativeFunction(
            Process.getModuleByName("pddworkbenchdata.dll").getExportByName("?GetInstance@IUserCenter@@SAPEAV1@XZ"),
            'pointer',
            []
        )();
        const tree = new StdTree(instance.add(0x168+8).readPointer());
        return tree.values(n => new StdString(n.data().add(0x20)).read());
    },
    getcurrenttoids: function () {
        const instance = new NativeFunction(
            Process.getModuleByName("pddworkbenchdata.dll").getExportByName("?GetInstance@IUserCenter@@SAPEAV1@XZ"),
            'pointer',
            []
        )();
        const tree = new StdTree(instance.add(0x2f8+8).readPointer());
        return tree.values(n => new StdString(n.data().add(0x20)).read());
    },
    test: function () {
        // new NativeFunction(
        //     Process.mainModule.add(0x3D3F0),
        //     'void',
        //     ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']
        // )(r13_830, mallcsid, customerid, message, message, r13_850, Memory.alloc(16), token);

        new NativeFunction(
            Process.getModuleByName('user32.dll').getExportByName('PostMessageW'),
            'bool',
            ['pointer', 'uint', 'pointer', 'pointer']
        )(ptr(0x5B04CA), 0x140E, Memory.allocUtf8String("cs_465616878_166414339"), Memory.allocUtf8String("7944428353327"));
    }
};