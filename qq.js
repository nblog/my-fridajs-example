///<reference path='C:\\Users\\r0th3r\\OneDrive\\Codes\\index.d.ts'/>



function assert (condition, msg) {
    if (!condition) throw new Error(`[ass] ${msg}`)
}



let symbols = {
    krnlutil: function() {
        return Process.getModuleByName("kernelutil.dll");
    },

    recvmsg: function() {
        let msg = symbols.krnlutil().enumerateExports().filter(function(e) {
            return e.name.includes( "CheckVideoMsg@Msg" );
        });

        assert(msg.length == 1, "recvmsg() failed to find CheckVideoMsg");

        return msg[0].address;
    }
};




function to_human_time( timestamp_s ) {
    let date = new Date(timestamp_s * 1000);
    let year = date.getFullYear();
    let month = date.getMonth() + 1;
    let day = date.getDate();
    let hour = date.getHours() + 8; /* GMT+8 */
    let minute = date.getMinutes();
    let second = date.getSeconds();
    return `${hour}:${minute}:${second}`;
}


let SysFreeString = new NativeFunction(
    Module.getExportByName("oleaut32.dll", "SysFreeString"),
    "void", [ "pointer" ]);

class CTXStringW {
    #bstr = NULL;

    constructor(stringPtr=NULL) { 
        this.#bstr = stringPtr;
    }

    get str() { 
        let buffer = this.#bstr.readPointer().readUtf16String();
        // SysFreeString(this.#bstr); /* ~CTXStringW */
        return String(buffer);
    }
}




let GetSelfUin = function() {
    return new NativeFunction(
        symbols.krnlutil().getExportByName("?GetSelfUin@Contact@Util@@YAKXZ"),
        "uint", [], "mscdecl")();
}

let GetGroupName = function(gid=Number(0)) {
    let fn = new NativeFunction(
    symbols.krnlutil().getExportByName("?GetGroupName@Group@Util@@YA?AVCTXStringW@@KH@Z"),
    "pointer", [ "pointer", "uint", "int" ], "mscdecl");
    let m = Memory.alloc( Process.pointerSize );
    return new CTXStringW( fn( m, gid, 0 ) ).str;
}

let GetNickname = function(uid=Number(0)) {
    let fn = new NativeFunction(
    symbols.krnlutil().getExportByName("?GetNickname@Contact@Util@@YA?AVCTXStringW@@K@Z"),
    "pointer", [ "pointer", "uint" ], "mscdecl");
    let m = Memory.alloc( Process.pointerSize );
    return new CTXStringW( fn( m, uid ) ).str;
}


let GetMsgTime = function(msgpack=NULL) {
    return new NativeFunction(
        symbols.krnlutil().getExportByName("?GetMsgTime@Msg@Util@@YA_JPAUITXMsgPack@@@Z"),
        "int64", [ "pointer" ], "mscdecl")(msgpack);
}

let GetMsgAbstract = function(msgpack=NULL) {
    let fn = new NativeFunction(
    symbols.krnlutil().getExportByName("?GetMsgAbstract@Msg@Util@@YA?AVCTXStringW@@PAUITXMsgPack@@@Z"),
    "pointer", [ "pointer", "pointer" ], "mscdecl");
    let m = Memory.alloc( Process.pointerSize );
    return new CTXStringW( fn( m, msgpack ) ).str;
}



rpc.exports = {
    recvmsg: function() {
        let fnAddr = symbols.recvmsg();

        Interceptor.attach(fnAddr, {
            onEnter: function(args) {
                // let group = args[0].toInt32();
                let sender_uid = Number(args[1]);
                // let uid2 = Number(args[2]);
                let group_uid = Number(args[3]);

                let msg_time = to_human_time( GetMsgTime(args[4]) );

                let msg_content = GetMsgAbstract( args[4] );

                let sender_name = GetNickname( sender_uid );

                if (group_uid) {
                    let group_name = GetGroupName( group_uid );
                    console.log(`${group_name}<${group_uid}> `);
                }

                console.log((group_uid ? "    " : "") + `${sender_name}<${sender_uid}> ${msg_time}`);

                console.log((group_uid ? "    " : "") + `${msg_content}`);
            }
        });
    }
};
