/// <reference path="C:/Users/r0th3r/OneDrive/Code/index.d.ts" />

/**
 * CDP-Enabler (Frida)
 * Usage:
 * uvx --from frida-tools frida -l cdp-enabler.js -p <chrome_pid_main>
 */

const CDP_PORT = 9222;

// TCPServerSocketFactory layout (Chrome uses libc++ std::string):
//   x64: vftable @0x00 (8B), std::string @0x08 (24B), port @0x20, total 40
//   x86: vftable @0x00 (4B), std::string @0x04 (12B), port @0x10, total 20
const IS64 = Process.pointerSize === 8;
const FACTORY_SIZE = IS64 ? 40 : 20;
const STRING_OFF = Process.pointerSize;
const PORT_OFF = STRING_OFF + (IS64 ? 24 : 12);

const log = function (tag, ...args) {
  const tid = Process.getCurrentThreadId();
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`[frida][${ts}] ${tag}:`, ...args);
};

function findVtable(chromeDll, createForHttpServerAddr) {
  const rdata = chromeDll.enumerateSections().find(s => s.name === '.rdata');
  if (!rdata) {
    log('error', '.rdata not found');
    return null;
  }

  log('vtable', `Scanning .rdata...`);

  for (let offset = 0; offset < rdata.size - Process.pointerSize * 2; offset += Process.pointerSize) {
    try {
      const addr = rdata.address.add(offset);
      const entry1 = addr.add(Process.pointerSize).readPointer();

      if (entry1.equals(createForHttpServerAddr)) {
        log('vtable', `found @ .rdata+0x${offset.toString(16)}`);
        return addr;
      }
    } catch (e) { }
  }

  log('vtable', 'vtable not found');

  return null;
}


(function () {
  log('main', '=== CDP-Enabler (Frida) ===');

  const CONFIG = {
    moduleName: Process.mainModule.name,
    operatorNew: 0, // void * __cdecl operator new(unsigned __int64)
    startRemoteDebuggingServer: 0, // content::DevToolsAgentHost::StartRemoteDebuggingServer
    createForHttpServer: 0, // TCPServerSocketFactory::CreateForHttpServer
  };

  const chromeDll = Process.getModuleByName(CONFIG.moduleName);
  log('main', `chrome.dll @ ${chromeDll.base}`);

  const createForHttpServerAddr = chromeDll.base.add(CONFIG.createForHttpServer);
  const startRemoteDebuggingServerAddr = chromeDll.base.add(CONFIG.startRemoteDebuggingServer);
  const operatorNewAddr = chromeDll.base.add(CONFIG.operatorNew);

  log('addr', `CreateForHttpServer @chrome.dll +0x${CONFIG.createForHttpServer.toString(16)}`);
  log('addr', `StartRemoteDebuggingServer @chrome.dll +0x${CONFIG.startRemoteDebuggingServer.toString(16)}`);
  log('addr', `operator new @chrome.dll +0x${CONFIG.operatorNew.toString(16)}`);

  const vtableAddr = findVtable(chromeDll, createForHttpServerAddr);
  if (!vtableAddr) {
    log('error', 'Failed to find vtable');
    return;
  }

  log('cdp', 'Starting CDP...');

  const factory = new NativeFunction(operatorNewAddr, 'pointer', ['size_t'], (IS64 ? 'win64' : 'mscdecl'))(FACTORY_SIZE);
  if (factory.isNull()) {
    log('error', 'allocation failed');
    return;
  }

  // TCPServerSocketFactory
  factory.writeByteArray(new Uint8Array(FACTORY_SIZE).fill(0));
  factory.add(0).writePointer(vtableAddr);
  factory.add(STRING_OFF).writeU8('127.0.0.1'.length << 1); // libc++ std::string SSO size<<1 (18)
  factory.add(STRING_OFF + 1).writeUtf8String('127.0.0.1');
  factory.add(PORT_OFF).writeU16(CDP_PORT);

  log('factory', `object @ ${factory}`);

  const factoryPtrStorage = Memory.alloc(Process.pointerSize);
  factoryPtrStorage.writePointer(factory);

  log('call', 'Calling StartRemoteDebuggingServer...');
  log('call', `  &factory_ptr = ${factoryPtrStorage} -> ${factory}`);

  try {
    // content::DevToolsAgentHost::StartRemoteDebuggingServer
    // void(unique_ptr<TCPServerSocketFactory>*, FilePath*, FilePath*)
    // base::FilePath holds one std::string: 24B on x64, 12B on x86
    const filePathSize = STRING_OFF + (IS64 ? 16 : 8);
    new NativeFunction(
      startRemoteDebuggingServerAddr,
      'void',
      ['pointer', 'pointer', 'pointer'],
      (IS64 ? 'win64' : 'mscdecl')
    )((IS64 ? factoryPtrStorage : factory), Memory.alloc(filePathSize), Memory.alloc(filePathSize));
    log('success', `CDP enabled! Test: curl http://127.0.0.1:${CDP_PORT}/json/version`);
  } catch (e) {
    log('error', `Failed: ${e.message}`);
    log('stack', e.stack);
  }
})();
