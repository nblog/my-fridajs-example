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
    constructor(stringPtr) { 
        let bstr = ptr(stringPtr); 
        this._str = ""; if(bstr.isNull()) return;
        this._str = bstr.readPointer().readUtf16String();
        SysFreeString(bstr); /* ~CTXStringW */
    }

    get str() { return this._str; }
}


let GetSelfUin = new NativeFunction(
    symbols.krnlutil().getExportByName("?GetSelfUin@Contact@Util@@YAKXZ"),
    "uint", [], "mscdecl");

let GetMsgTime = new NativeFunction(
    symbols.krnlutil().getExportByName("?GetMsgTime@Msg@Util@@YA_JPAUITXMsgPack@@@Z"),
    "int64", [ "pointer" ], "mscdecl");

let GetGroupName = new NativeFunction(
    symbols.krnlutil().getExportByName("?GetGroupName@Group@Util@@YA?AVCTXStringW@@KH@Z"),
    "pointer", [ "pointer", "uint", "int" ], "mscdecl");

let GetNickname = new NativeFunction(
    symbols.krnlutil().getExportByName("?GetNickname@Contact@Util@@YA?AVCTXStringW@@K@Z"),
    "pointer", [ "pointer", "uint" ], "mscdecl");

let GetMsgAbstract = new NativeFunction(
    symbols.krnlutil().getExportByName("?GetMsgAbstract@Msg@Util@@YA?AVCTXStringW@@PAUITXMsgPack@@@Z"),
    "pointer", [ "pointer", "pointer" ], "mscdecl");



rpc.exports = {
    recvmsg: function() {
        let fnAddr = symbols.recvmsg();

        Interceptor.attach(fnAddr, {
            onEnter: function(args) {
                // let group = args[0].toInt32();
                let sender_uid = Number(args[1]);
                // let uid2 = Number(args[2]);
                let group_uid = Number(args[3]);

                let msg_time = to_human_time(GetMsgTime(args[4]));

                let m = Memory.alloc( Process.pointerSize );
                let msg_content = new CTXStringW(
                    GetMsgAbstract( m, args[4] )).str;

                m = Memory.alloc( Process.pointerSize );
                let sender_name = new CTXStringW(
                    GetNickname( m, sender_uid )).str;

                if (group_uid) {
                    m = Memory.alloc( Process.pointerSize );
                    let group_name = new CTXStringW( 
                        GetGroupName( m, group_uid, 0 )).str;
                    console.log(`${group_name}<${group_uid}> `);
                }

                console.log((group_uid ? "    " : "") + `${sender_name}<${sender_uid}> ${msg_time}`);

                console.log((group_uid ? "    " : "") + `${msg_content}`);
            }
        });
    }
};