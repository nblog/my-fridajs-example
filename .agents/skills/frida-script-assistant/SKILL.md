---
name: frida-script-assistant
description: >
  Designs and generates Frida JavaScript/TypeScript single-file scripts or full agents
  for dynamic reverse engineering on multiple platforms. Handles function hooking/tracing
  (Interceptor, NativeFunction, Stalker), Java/ObjC runtime interaction, memory/module
  inspection, and produces logged, debuggable output.
---

# Frida Script Assistant

## Workflow
- Start with Socratic clarifications: platform (Android/iOS/macOS/Windows/Linux), target process/package, architecture, goal (hook/trace/dump/patch/anti-anti), target symbols/addresses/APIs, logging format, and any constraints (root/jailbreak, SELinux/sandbox, timing).
- If requirements are fuzzy or multiple approaches exist, ask the minimum follow-up questions before coding. Propose MVP vs. enhanced/stealth plan when useful.
- Choose output form: single JS injector vs. TS agent (frida-agent-example style). Offer staged outputs: MVP (core hooks/logs), then enhanced (filters, arg/ret decoding, anti-detection).

## Index.d.ts guardrail (JavaScript only)
- When generating **JavaScript** scripts (not TypeScript agents), include `///<reference path='index.d.ts'/>` at the top for IDE type hints.
- Before emitting JS code, check whether `index.d.ts` exists in the workspace (prefer `rg --files -g "index.d.ts"`).
  * If missing, suggest: `curl https://github.com/DefinitelyTyped/DefinitelyTyped/raw/refs/heads/master/types/frida-gum/index.d.ts -o index.d.ts`.

## Default logging & safety
- Use concise, structured logs (e.g., `[frida] tag: detail`, JSON.stringify for complex data).
- Wrap risky sections in try/catch; fail loudly with context. Normalize addresses with `ptr(...)`.
- Provide detach/cleanup guidance (e.g., Interceptor.detachAll()) when relevant.

## Observability & backtrace logging
- **Backtrace**: Use `Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress)` to capture native call stack; prefer `Backtracer.FUZZY` for stripped binaries.
- **Address resolution**: Always resolve addresses to `module+offset` via `DebugSymbol.fromAddress(addr)` or manual calculation `addr.sub(module.base)` for reproducible offsets.
- **Caller info**: Log `this.returnAddress` in `onEnter` to identify immediate caller; combine with backtrace for full context.
- **Structured hook logs**: Include hook name, module, offset, thread ID (`Process.getCurrentThreadId()`), and timestamp for correlation.
- **Java backtrace** (Android): Use `Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new())` for Java-layer call chains.
- **Hexdump for buffers**: Use `hexdump(ptr, {length: N, ansi: true})` to inspect memory regions with visual formatting.

## JS single-file scaffold (Example)
```js
/// <reference path="index.d.ts" />

// Structured logging with timestamp and thread ID
const log = (tag, ...args) => {
  const tid = Process.getCurrentThreadId();
  console.log(`[frida][t:${tid}] ${tag}:`, ...args);
};

// Backtrace helper: returns formatted call stack with module+offset
function bt(ctx, limit = 8) {
  return Thread.backtrace(ctx, Backtracer.ACCURATE)
    .slice(0, limit)
    .map(addr => {
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

// Address resolver: returns { module, offset, symbol }
function addrInfo(addr) {
  const sym = DebugSymbol.fromAddress(addr);
  const mod = Process.findModuleByAddress(addr);
  return {
    module: mod?.name || 'unknown',
    offset: mod ? addr.sub(mod.base).toString(16) : '0',
    symbol: sym.name || null
  };
}

function hookExport(moduleName, exportName) {
  const mod = Process.getModuleByName(moduleName);
  const addr = mod.getExportByName(exportName);
  if (!addr) { log('miss', moduleName, exportName); return; }
  
  const offset = addr.sub(mod.base);
  log('hook', `${moduleName}!${exportName} @ ${addr} (${moduleName}+0x${offset.toString(16)})`);
  
  Interceptor.attach(addr, {
    onEnter(args) {
      this.caller = addrInfo(this.returnAddress);
      this.fileDescriptor = args[0].toInt32();
      
      log('enter', exportName, 
          `fd=${this.fileDescriptor}`,
          `caller=${this.caller.module}+0x${this.caller.offset}`);
      
      // Full backtrace (uncomment when needed):
      // log('backtrace', exportName, '\n' + bt(this.context).join('\n  <- '));
    },
    onLeave(retval) {
      const ret = retval.toInt32();
      if (ret > 0) {
        log('leave', exportName, `ret=${ret}`);
      }
    }
  });
}

function main() {
  // hookExport('libc.so', 'read');
}
```

## TypeScript agent pointers
- Clone starter: `git clone https://github.com/oleavr/frida-agent-example` then `cd frida-agent-example`.
- Init deps: `npm install` (assumes Node toolchain present).
- Build: `npm run build`.
- Run: `frida -l _agent.js -U -f com.example.android`.
- In `agent/index.ts`, keep the same logging; export minimal API surface. Map helpers (address resolvers, Java helpers) as needed.

## Common API cues
- JavaScript API Doc: https://frida.re/docs/javascript-api/#table-of-contents
- [`Interceptor`](https://github.com/frida/frida-website/blob/main/_i18n/en/_docs/javascript-api.md#instruction) for hooking functions, [`NativeFunction`](https://github.com/frida/frida-website/blob/main/_i18n/en/_docs/javascript-api.md#nativefunction) for calling exports/pointers, [`Module.enumerateExports/Imports`](https://github.com/frida/frida-website/blob/main/_i18n/en/_docs/javascript-api.md#module) for discovery, [`Memory.read/write/patch`](https://github.com/frida/frida-website/blob/main/_i18n/en/_docs/javascript-api.md#memory) for data capture or inline patching, [`Stalker`](https://github.com/frida/frida-website/blob/main/_i18n/en/_docs/javascript-api.md#stalker) for instruction-level tracing, `Java/ObjC` runtime APIs when on Android/iOS.

## Delivery checklist
- Confirm platform/arch/target and intended result (log, modify behavior, dump data).
- Include reference header + index.d.ts check note.
- Provide execution snippet (e.g., `frida -l script.js -U -f <pkg>`).
  * For remote JS debugging, use V8 runtime + debug: `frida --runtime=v8 --debug -l script.js -U -f <pkg>` to enable the Node.js-compatible script debugger and attach via `Chrome DevTools`.
- If output is long or multi-stage, present MVP first, then optional enhancements/stealth measures.

## Reference resources (read when needed)
- Frida CLI tooling and workflows: https://github.com/frida/frida-tools (reference for `frida`, `frida-trace`, `frida-discover`, etc.).
- Frida JS script unit test patterns: https://github.com/frida/frida-gum/blob/main/tests/gumjs/script.c (useful for assertion style, hooking behavior checks).
