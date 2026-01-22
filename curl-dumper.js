///<reference path='C:/Users/r0th3r/OneDrive/Code/index.d.ts'/>

// https://learn.microsoft.com/windows-hardware/drivers/debugger/general-environment-variables
/*
    $env:_NT_SYMBOL_PATH="$env:ProgramData\Dbg\sym"
    frida -l .\curl-dumper.js -f $env:SYSTEMROOT\System32\curl.exe ipinfo.io
*/


// https://github.com/frida/frida-gum/blob/main/gum/backend-dbghelp/gumsymbolutil-dbghelp.c#L151
DebugSymbol.load(Process.enumerateModules()[0].name);

let symbols = {
    abi: 8 == Process.pointerSize ? 'default' : 'mscdecl',

    mod_curl: Process.findModuleByName('libcurl.dll') || 
        Process.findModuleByName('libcurl.so') || 
        Process.findModuleByName('libcurl.dylib') ||
        Process.enumerateModules()[0],

    ptr_curl_easy_setopt: () => {
        return DebugSymbol.fromName('curl_easy_setopt')?.address ||
            symbols.mod_curl.getExportByName('curl_easy_setopt');
    },
    ptr_curl_easy_perform: () => {
        return DebugSymbol.fromName('curl_easy_perform')?.address ||
            symbols.mod_curl.getExportByName('curl_easy_perform');
    },

    /* https://curl.se/libcurl/c/curl_easy_setopt.html */
    curl_easy_setopt: function(handle, option, parameter) {
        return new NativeFunction(
            symbols.ptr_curl_easy_setopt(),
            'int', ['pointer', 'uint', 'pointer'], symbols.abi)(handle, option, parameter);
    },
    /* https://curl.se/libcurl/c/curl_easy_perform.html */
    curl_easy_perform: function(easy_handle) {
        return new NativeFunction(
            symbols.ptr_curl_easy_perform(),
            'int', ['pointer'], symbols.abi)(easy_handle);
    }
};


/* https://curl.se/libcurl/c/CURLOPT_DEBUGFUNCTION.html */
const my_trace = new NativeCallback((handle, type, data, size, clientp) => {
    let curl_infotype = {
        CURLINFO_TEXT: 0,
        CURLINFO_HEADER_IN: 1,
        CURLINFO_HEADER_OUT: 2,
        CURLINFO_DATA_IN: 3,
        CURLINFO_DATA_OUT: 4,
        CURLINFO_SSL_DATA_IN: 5,
        CURLINFO_SSL_DATA_OUT: 6,
    }

    switch (type) {
        case curl_infotype.CURLINFO_TEXT:
            console.log(`== Info: ` + `${data.readUtf8String()}`);
        default: /* in case a new one is introduced to shock us */
            return 0;
        case curl_infotype.CURLINFO_HEADER_OUT:
            console.log(`=> Send header` + `, ${size} bytes (0x${size.toString(16)})`);
            break;
        case curl_infotype.CURLINFO_DATA_OUT:
            console.log(`=> Send data` + `, ${size} bytes (0x${size.toString(16)})`);
            break;
        case curl_infotype.CURLINFO_SSL_DATA_OUT:
            console.log(`=> Send SSL data` + `, ${size} bytes (0x${size.toString(16)})`);
            break;
        case curl_infotype.CURLINFO_HEADER_IN:
            console.log(`<= Recv header` + `, ${size} bytes (0x${size.toString(16)})`);
            break;
        case curl_infotype.CURLINFO_DATA_IN:
            console.log(`<= Recv data` + `, ${size} bytes (0x${size.toString(16)})`);
            break;
        case curl_infotype.CURLINFO_SSL_DATA_IN:
            console.log(`<= Recv SSL data` + `, ${size} bytes (0x${size.toString(16)})`);
            break;
    }

    /* dump data */
    const maxDumpSize = 128;
    console.log(`${hexdump(data, {length: Math.min(size, maxDumpSize), ansi: true})}`);
    if (size > maxDumpSize)
        console.log(`... (${size - maxDumpSize} bytes omitted)`);

    return 0;
}, 'int', ['pointer', 'int', 'pointer', 'size_t', 'pointer'], symbols.abi);

function installCurlTrace() {
    Interceptor.replace(symbols.ptr_curl_easy_perform(),
        new NativeCallback((easy_handle) => {
            /* Apr 15, 2002: https://github.com/curl/curl/blob/curl-7_9_6/include/curl/curl.h#L534 */
            let CURLOPT_VERBOSE = 41;
            let CURLOPT_DEBUGFUNCTION = 20000 + 94;
            symbols.curl_easy_setopt(easy_handle, CURLOPT_DEBUGFUNCTION, ptr(my_trace));
            symbols.curl_easy_setopt(easy_handle, CURLOPT_VERBOSE, ptr(1));

            return symbols.curl_easy_perform(easy_handle);
        }, 'int', ['pointer'], symbols.abi)
    );
}

/**
 * Patches NtProtectVirtualMemory to be a no-op to prevent VMProtect from protecting its own memory regions.
 * This bypasses memory protection checks on Windows systems using VMProtect obfuscation.
**/
new Promise(() => {
    setTimeout(() => {
        const patched = Process.getModuleByName('ntdll.dll').getExportByName('NtProtectVirtualMemory');
        if (0xe9 == patched.readU8()) {
            Memory.patchCode(patched, 64, code => {
                let cw = new X86Writer(code, { pc: patched });
                if (8 == Process.pointerSize)
                    cw.putMovRegReg('r10', 'rcx');
                cw.putMovRegU32('eax', 0x50);
                cw.flush();
            });
            console.log(`Patched NtProtectVirtualMemory`);
        }

        installCurlTrace();
    }, 100);
});
