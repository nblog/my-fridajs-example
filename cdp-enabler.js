/// <reference path="C:/Users/r0th3r/OneDrive/Code/index.d.ts" />

/**
 * CDP-Enabler (Frida)
 * 
 * Enable CDP and evaluate renderer JavaScript from a Frida agent on Windows.
 * Import this module and fill CONFIG with the target's RVAs before calling RPC.
 * The factory layout follows the original cdp-enabler.js (Chromium libc++).
 * 
 * Usage:
 * uvx --from frida-tools frida -l cdp-enabler.js -p <chrome_pid_main>
 */

export const CONFIG = {
  moduleName: Process.mainModule.name,
  operatorNew: 0,
  startRemoteDebuggingServer: 0,
  createForHttpServer: 0,
};

const DEFAULT_PORT = 9222;
const DEFAULT_JS = `(() => {
  let banner = document.getElementById('frida-cdp-enabler2');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'frida-cdp-enabler2';
    banner.style.cssText = 'position:fixed;top:12px;left:12px;z-index:2147483647;' +
      'padding:12px 18px;background:#176340;color:white;border-radius:8px;font:16px sans-serif';
    document.body.appendChild(banner);
  }
  banner.textContent = 'Frida CDP: 注入成功 🚀';
  window.__fridaCdpEnabler2 = (window.__fridaCdpEnabler2 || 0) + 1;
  return {title: document.title, text: banner.textContent, count: window.__fridaCdpEnabler2};
})()`;

const IS64 = Process.pointerSize === 8;
const STRING_SIZE = IS64 ? 24 : 12;
const FACTORY_SIZE = IS64 ? 40 : 20;
const STRING_OFF = Process.pointerSize;
const PORT_OFF = STRING_OFF + STRING_SIZE;
const BUFFER_SIZE = 16 * 1024;
const TIMEOUT_MS = 10 * 1000;
let cdpPort = DEFAULT_PORT;
let commandId = 0;

function findVtable(module, createForHttpServer) {
  const section = module.enumerateSections().find(item => item.name === '.rdata');
  if (!section) throw new Error('.rdata section not found');
  const slot = Memory.alloc(Process.pointerSize).writePointer(createForHttpServer);
  const pattern = Array.from(new Uint8Array(slot.readByteArray(Process.pointerSize)),
    byte => byte.toString(16).padStart(2, '0')).join(' ');
  const match = Memory.scanSync(section.address, section.size, pattern).find(item =>
    item.address.sub(section.address).toUInt32() % Process.pointerSize === 0 &&
    item.address.compare(section.address.add(Process.pointerSize)) >= 0);
  if (!match) throw new Error('TCPServerSocketFactory vtable not found');
  return match.address.sub(Process.pointerSize);
}

/** Start the native server with the configured offsets, then confirm HTTP readiness. */
export async function enable_cdp(port = DEFAULT_PORT) {
  port ??= DEFAULT_PORT; // Frida RPC supplies null when its binary-data argument is absent.
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid CDP port');
  if (!CONFIG.operatorNew || !CONFIG.startRemoteDebuggingServer || !CONFIG.createForHttpServer) {
    throw new Error('Set the three CONFIG offsets before calling enable_cdp()');
  }
  const module = Process.getModuleByName(CONFIG.moduleName);
  const vtable = findVtable(module, module.base.add(CONFIG.createForHttpServer));
  const abi = IS64 ? 'win64' : 'mscdecl';
  const allocate = new NativeFunction(module.base.add(CONFIG.operatorNew), 'pointer', ['size_t'], abi);
  const start = new NativeFunction(module.base.add(CONFIG.startRemoteDebuggingServer),
    'void', ['pointer', 'pointer', 'pointer'], abi);
  const factory = allocate(FACTORY_SIZE);
  if (factory.isNull()) throw new Error('operator new returned NULL');
  factory.writeByteArray(new Uint8Array(FACTORY_SIZE));
  factory.writePointer(vtable);
  factory.add(STRING_OFF).writeU8('127.0.0.1'.length << 1);
  factory.add(STRING_OFF + 1).writeUtf8String('127.0.0.1');
  factory.add(PORT_OFF).writeU16(port);
  const factoryPointer = Memory.alloc(Process.pointerSize).writePointer(factory);
  const emptyPath = () => Memory.alloc(STRING_SIZE).writeByteArray(new Uint8Array(STRING_SIZE));
  start(IS64 ? factoryPointer : factory, emptyPath(), emptyPath());
  // Chromium now owns the factory allocated with its own operator new.
  cdpPort = port;
  const deadline = Date.now() + TIMEOUT_MS;
  let lastError;
  do {
    try {
      const version = getJson('/json/version');
      return { port, endpoint: `http://127.0.0.1:${port}`, browser: version.Browser };
    } catch (error) { lastError = error; }
    await new Promise(resolve => setTimeout(resolve, 100));
  } while (Date.now() < deadline);
  throw lastError;
}

// GumJS has no built-in fetch/WebSocket; WinHTTP supplies both transports.
const winhttp = Module.load('winhttp.dll');
const bind = (name, result, args) => new SystemFunction(winhttp.getExportByName(name), result, args,
  { abi: IS64 ? 'win64' : 'stdcall' });
const api = {
  open: bind('WinHttpOpen', 'pointer', ['pointer', 'uint', 'pointer', 'pointer', 'uint']),
  connect: bind('WinHttpConnect', 'pointer', ['pointer', 'pointer', 'uint16', 'uint']),
  request: bind('WinHttpOpenRequest', 'pointer',
    ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'uint']),
  timeouts: bind('WinHttpSetTimeouts', 'int', ['pointer', 'int', 'int', 'int', 'int']),
  option: bind('WinHttpSetOption', 'int', ['pointer', 'uint', 'pointer', 'uint']),
  send: bind('WinHttpSendRequest', 'int',
    ['pointer', 'pointer', 'uint', 'pointer', 'uint', 'uint', 'size_t']),
  response: bind('WinHttpReceiveResponse', 'int', ['pointer', 'pointer']),
  headers: bind('WinHttpQueryHeaders', 'int',
    ['pointer', 'uint', 'pointer', 'pointer', 'pointer', 'pointer']),
  read: bind('WinHttpReadData', 'int', ['pointer', 'pointer', 'uint', 'pointer']),
  upgrade: bind('WinHttpWebSocketCompleteUpgrade', 'pointer', ['pointer', 'size_t']),
  wsSend: bind('WinHttpWebSocketSend', 'uint', ['pointer', 'int', 'pointer', 'uint']),
  wsRead: bind('WinHttpWebSocketReceive', 'uint', ['pointer', 'pointer', 'uint', 'pointer', 'pointer']),
  close: bind('WinHttpCloseHandle', 'int', ['pointer']),
};
const uint32 = value => Memory.alloc(4).writeU32(value);

function checked(result, name) {
  if (typeof result.value === 'number' ? result.value === 0 : result.value.isNull()) {
    throw new Error(`${name}: Win32 error ${result.lastError}`);
  }
  return result.value;
}

function checkWebSocket(result) {
  if (result.value !== 0) throw new Error(`WebSocket: Win32 error ${result.value}`);
}

/* A request owns its handles and releases them from child to parent. */
function withRequest(host, port, path, websocket, action) {
  const handles = [];
  const own = (result, name) => { const handle = checked(result, name); handles.push(handle); return handle; };
  try {
    const session = own(api.open(Memory.allocUtf16String('Frida-CDP'), 1, NULL, NULL, 0), 'WinHttpOpen');
    checked(api.timeouts(session, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS), 'WinHttpSetTimeouts');
    const connection = own(api.connect(session, Memory.allocUtf16String(host), port, 0), 'WinHttpConnect');
    const request = own(api.request(connection, Memory.allocUtf16String('GET'),
      Memory.allocUtf16String(path), NULL, NULL, NULL, 0), 'WinHttpOpenRequest');
    // WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET = 114.
    if (websocket) checked(api.option(request, 114, NULL, 0), 'WinHttpSetOption');
    checked(api.send(request, NULL, 0, NULL, 0, 0, 0), 'WinHttpSendRequest');
    checked(api.response(request, NULL), 'WinHttpReceiveResponse');
    const status = uint32(0);
    checked(api.headers(request, 19 | 0x20000000, NULL, status, uint32(4), NULL), 'WinHttpQueryHeaders');
    if (status.readU32() !== (websocket ? 101 : 200)) throw new Error(`HTTP ${status.readU32()}: ${path}`);
    return action(websocket ? own(api.upgrade(request, 0), 'WinHttpWebSocketCompleteUpgrade') : request);
  } finally {
    for (const handle of handles.reverse()) api.close(handle);
  }
}

/* Join bytes before decoding so UTF-8 characters split across reads remain intact. */
function readText(handle, websocket = false) {
  const buffer = Memory.alloc(BUFFER_SIZE);
  const count = uint32(0), type = uint32(0), chunks = [];
  let total = 0;
  while (true) {
    if (websocket) {
      checkWebSocket(api.wsRead(handle, buffer, BUFFER_SIZE, count, type));
      if (type.readU32() !== 2 && type.readU32() !== 3) throw new Error('CDP WebSocket closed or sent non-text data');
    } else {
      checked(api.read(handle, buffer, BUFFER_SIZE, count), 'WinHttpReadData');
    }
    const length = count.readU32();
    chunks.push(buffer.readByteArray(length));
    total += length;
    if (websocket ? type.readU32() === 2 : length === 0) break;
  }
  const text = Memory.alloc(total + 1);
  let offset = 0;
  for (const chunk of chunks) { text.add(offset).writeByteArray(chunk); offset += chunk.byteLength; }
  text.add(total).writeU8(0);
  return text.readUtf8String(total);
}

function getJson(path) {
  return withRequest('127.0.0.1', cdpPort, path, false, request => JSON.parse(readText(request)));
}

/** Evaluate in one page selected by exact filter fields; retain the CDP RemoteObject result. */
export function exec_js(filter = { title: 'Electron' }, expression = DEFAULT_JS) {
  expression ??= DEFAULT_JS;
  filter ??= { title: 'Electron' };
  const pages = getJson('/json/list').filter(page => page.type === 'page');
  const matches = pages.filter(page => Object.entries(filter).every(([key, value]) => page[key] === value));
  if (matches.length !== 1) {
    throw new Error(`Expected one page, matched ${matches.length}; pages: ` +
      JSON.stringify(pages.map(({ id, title, url }) => ({ id, title, url }))));
  }
  const page = matches[0];
  const endpoint = /^ws:\/\/([^/:]+):(\d+)(\/[^\r\n]*)$/.exec(page.webSocketDebuggerUrl);
  if (!endpoint) throw new Error('Expected a ws://host:port/path CDP endpoint');
  return withRequest(endpoint[1], Number(endpoint[2]), endpoint[3], true, socket => {
    const id = ++commandId;
    const command = JSON.stringify({ id, method: 'Runtime.evaluate', params: {
      expression, awaitPromise: true, returnByValue: true, timeout: TIMEOUT_MS,
    } });
    const text = Memory.allocUtf8String(command);
    let length = 0;
    while (text.add(length).readU8() !== 0) length++;
    checkWebSocket(api.wsSend(socket, 2, text, length)); // UTF8_MESSAGE buffer type.
    while (true) {
      const message = JSON.parse(readText(socket, true));
      if (message.id !== id) continue;
      if (message.error) throw new Error(`CDP: ${JSON.stringify(message.error)}`);
      const { result, exceptionDetails } = message.result;
      if (exceptionDetails) throw new Error(exceptionDetails.exception?.description ?? exceptionDetails.text);
      return { target: { id: page.id, title: page.title, url: page.url }, result };
    }
  });
}

rpc.exports = { enable_cdp, exec_js };