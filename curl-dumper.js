///<reference path="index.d.ts"/>


let symbols = {
    /* custom */
    ptr_curl_easy_setopt: Module.getExportByName('libcurl.dll', 'curl_easy_setopt'),
    ptr_curl_easy_perform: Module.getExportByName('libcurl.dll', 'curl_easy_perform'),

    abi: 8 == Process.pointerSize ? 'default' : 'mscdecl',

    /* https://curl.se/libcurl/c/curl_easy_setopt.html */
    curl_easy_setopt: function(curl, option, parameter) {
        return new NativeFunction(
            symbols.ptr_curl_easy_setopt,
            'int', ['pointer', 'uint', 'pointer'], symbols.abi)(curl, option, parameter);
    },
    /* https://curl.se/libcurl/c/curl_easy_perform.html */
    curl_easy_perform: function(curl) {
        return new NativeFunction(
            symbols.ptr_curl_easy_perform,
            'int', ['pointer'], symbols.abi)(curl);
    }
};


/* https://curl.se/libcurl/c/CURLOPT_DEBUGFUNCTION.html */
let dumper = new NativeCallback((handle, type, data, size, clientp) => {

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
    console.log(`${hexdump(data, {length: size, ansi: true})}`);

    return 0;
}, 'int', ['pointer', 'int', 'pointer', 'size_t', 'pointer'], symbols.abi);



Interceptor.replace(symbols.ptr_curl_easy_perform, 
    new NativeCallback((curl) => {

        /* Apr 15, 2002: https://github.com/curl/curl/blob/curl-7_9_6/include/curl/curl.h#L534 */
        let CURLOPT_VERBOSE = 41;
        let CURLOPT_DEBUGFUNCTION = 20000 + 94;
        symbols.curl_easy_setopt(curl, CURLOPT_VERBOSE, ptr(1));
        symbols.curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, ptr(dumper));

        return symbols.curl_easy_perform(curl);
    }, 'int', ['pointer'], symbols.abi));
