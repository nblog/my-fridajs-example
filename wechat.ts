
import { addr_transform } from "./aobscan.js";


/*



*/
let addrHelper = new addr_transform("WechatWin.dll");

let symbols = {

    toVa: function(rva: number) {
        return addrHelper.va(rva);
    },

    revokemsg: function(allow=true) {
        /* 
            "On RevokeMsg svrId"
            8B CF E8 ?? ?? ?? ?? 83 C4 18 84 C0 0F 84 +0x2 call
        */
        let match = addrHelper.aobscan( "8B CF E8 ?? ?? ?? ?? 83 C4 18 84 C0 0F 84" );

        let fnAddr = addrHelper.va( addrHelper.call( match[0]["address"].add(2) ) ) ;

        if (!allow) {
            Interceptor.replace( fnAddr, new NativeCallback(() => {
                return Number(false);
            }, 'bool', []));
        } else Interceptor.revert( fnAddr );

        return fnAddr;
    },
    recvmsg: function() {
        /*
            "receive a unknown msg type: %d"
            E8 ?? ?? ?? ?? 83 C0 01 83 D2 00 52 50 E8 -0xA call
        */
        let match = addrHelper.aobscan( "E8 ?? ?? ?? ?? 83 C0 01 83 D2 00 52 50 E8" );

        let fnAddr = addrHelper.va( addrHelper.call( match[0]["address"].sub(0xa) ) ) ;

        return fnAddr;
    },

    /* 3.8.1.26 */
    wx_free: function(mem: NativePointer) {
        return new NativeFunction( 
            addrHelper.va( 0x21DE211 ), 
            'void', ['pointer'], 'stdcall')( mem );
    },
    wx_malloc: function(length: number) {
        return new NativeFunction( 
            addrHelper.va( 0x217AC91 ), 
            'pointer', ['size_t'], 'stdcall')( length );
    },
    view_sendtext: function(user: string, text: string) {
        let fnAddr = addrHelper.va( 0xB6A930 );
        let wx = new NativeFunction( fnAddr, 
            'void', ['pointer', 
            'pointer', 'pointer',   // user && text
            'pointer',              // notify@all
            'uint',                 // type
            'bool', 'uint'], 'fastcall');

        let wx_at = wx_string.alloc(); wx_at.str = "";  /* notify@all */
        let wx_user = wx_string.alloc(); wx_user.str = user;
        let wx_text = wx_string.alloc(); wx_text.str = text;

        wx( Memory.alloc(0x2a8), wx_user.data, wx_text.data, wx_at.data, 1, 0, 0 );
    },
    view_sendscreenshot(user: string, picture: string) {
        let env = new NativeFunction( 
            addrHelper.va( 0x65B2A0 ), 'pointer', [], 'mscdecl')( );

        let fnAddr = addrHelper.va( 0xB6A3F0 );
        let wx = new NativeFunction( fnAddr, 
            'void', ['pointer', 
            'pointer', 
            'pointer', 'pointer', // user && file
            'pointer', 'uint', 'uint', 'uint', 'uint'], 'thiscall');

        let wx_user = wx_string.alloc(); wx_user.str = user;
        let wx_file = wx_string.alloc(); wx_file.str = picture;

        wx( env, 
            Memory.alloc(0x2a8), 
            wx_user.data, wx_file.data, 
            NULL, 0, 0, 0, 0 );
    },
    view_sendcustomemoji: function(user: string, image: string) {
        /* CustomSmileyMgr */
        let env = new NativeFunction( 
            addrHelper.va( 0x69A7D0 ), 'pointer', [], 'mscdecl')( );

        let fnAddr = addrHelper.va( 0xAA9FD0 );
        let wx = new NativeFunction( fnAddr, 
            'void', ['pointer', 
            'pointer', 'uint', 'uint', 'uint', 'uint',  // image
            'pointer', 'uint', 'uint', 'uint', 'uint',  // unknown
            'pointer', 'uint', 'uint', 'uint', 'uint',  // user
            'uint',
            'pointer', 'uint', 'uint', 'uint', 'uint',  // unknown
            'bool', 'pointer'
        ], 'thiscall');

        let wx_user = wx_string.alloc(); wx_user.str = user;
        let wx_file = wx_string.alloc(); wx_file.str = image;

        wx( env,
            wx_file.buffer, wx_file.length, wx_file.length, 0, 0,
            NULL, 0, 0, 0, 0,
            wx_user.buffer, wx_user.length, wx_user.length, 0, 0,
            2,
            NULL, 0, 0, 0, 0,
            0, Memory.alloc( 8 ) );
    },
    view_sendfile: function(user: string, file: string) {
        /* AppMsgMgr */
        let env = new NativeFunction( 
            addrHelper.va( 0x65DF50 ), 'pointer', [], 'mscdecl')( );

        let fnAddr = addrHelper.va( 0xA10190 );
        let wx = new NativeFunction( fnAddr, 
            'void', ['pointer', 
            'pointer', 
            'pointer', 'uint', 'uint', 'uint', 'uint',  // user
            'pointer', 'uint', 'uint', 'uint', 'uint',  // file
            'pointer', 'uint', 'uint', 'uint', 'uint',  // unknown
            'uint',
            'pointer', 'uint', 'uint', 'uint', 'uint'   // unknown
        ], 'thiscall');

        let wx_user = wx_string.alloc(); wx_user.str = user;
        let wx_file = wx_string.alloc(); wx_file.str = file;

        wx( env,
            Memory.alloc(0x2a8),
            wx_user.buffer, wx_user.length, wx_user.length, 0, 0,
            wx_file.buffer, wx_file.length, wx_file.length, 0, 0,
            NULL, 0, 0, 0, 0,
            0,
            NULL, 0, 0, 0, 0 );
    },
}



class wx_string {
    #data = NULL; #c_str = NULL;

    constructor(data: NativePointer) {
        this.#data = data;
    }

    get data() { return this.#data; }
    set data(value) { this.#data = value; }
    get buffer() { return this.empty() ? NULL : this.data.readPointer(); }
    set buffer(value) { if (!this.data.isNull()) this.data.writePointer(value); }

    get length() { return this.data.add(Process.pointerSize).readU32(); }
    set length(value) { 
        this.data.add(Process.pointerSize).writeU32(value);
        this.data.add(Process.pointerSize * 2).writeU32(value);
    }

    get str() { return this.length ? String( this.buffer.readUtf16String() ) : ""; }
    set str(value) { 
        // this.#c_str = Memory.allocUtf16String(value);
        this.#c_str = symbols.wx_malloc((value.length + 1) * 2).writeUtf16String(value);
        this.buffer = this.#c_str; this.length = value.length;
    }

    empty() {
        return 0 == this.length;
    }

    clear() {
        this.length = 0; this.buffer = NULL;
    }

    static alloc() {
        /* [ 'pointer', 'uint', 'uint', 'uint', 'uint' ] */
        return new wx_string( Memory.alloc(20) );
    }
}

class recv_context {
    #pcontext = NULL;

    constructor(pcontext: NativePointer) {
        this.#pcontext = pcontext;
    }

    /*
        1: text
        3: image
        34: voice
        37: new friend
        42: card
        43: video
        47: custom emoji
        48: location
        49: file / share / link / money
        10000: system
    */
    get type() { return this.#pcontext.add(0x38).readU32(); }
    set type(value) { this.#pcontext.add(0x38).writeU32(value); }

    get self() { return 1 == this.#pcontext.add(0x3c).readU8(); }

    get target() { return new wx_string(this.#pcontext.add(0x48)); }

    get content() { return new wx_string(this.#pcontext.add(0x70)); }

    skip() {
        this.content.clear(); this.type = 0;
    }

    replace(content: string, type: number=0) {
        this.content.str = content; if (type) this.type = type;
    }
}




rpc.exports = {

    dbkey() {
        /*
            "On Set Md5 : %s"
            83 FF 20 75 15 85 F6 74 11 57 56 8D 88 +B +2 imm32
        */
        let dbkeyOffset = 0;
        {
            let match = addrHelper.aobscan( "83 FF 20 75 15 85 F6 74 11 57 56 8D 88" );
            dbkeyOffset = addrHelper.imm32( match[0]["address"].add(0xb).add(2) );
        }
        /*
            "On Set Info info md5 : %s, y : %s"
            83 C4 70 E8 ?? ?? ?? ?? FF 76 0C 8D 4D 08 FF 76 08 FF 76 04 FF 36 51 8B C8 +3 call
        */
        let match = addrHelper.aobscan( "83 C4 70 E8 ?? ?? ?? ?? FF 76 0C 8D 4D 08 FF 76 08 FF 76 04 FF 36 51 8B C8" );

        let fnAddr = addrHelper.va( addrHelper.call( match[0]["address"].add(3) ) );

        let loginMgr = new NativeFunction(fnAddr, 'pointer', [], 'mscdecl')();

        let dbkey_20 = loginMgr.add(dbkeyOffset).readPointer();

        /* not logged in */
        if (dbkey_20.isNull()) { return null; }

        let dbkeyLength = loginMgr.add(dbkeyOffset).add(Process.pointerSize).readU32();
        /*
            PRAGMA hexkey = \'{}\';
            PRAGMA cipher_page_size = 4096;
            PRAGMA kdf_iter = 64000;
            PRAGMA cipher_hmac_algorithm = HMAC_SHA1;
            PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;
        */
        let userdir = new wx_string(loginMgr.add(0x10)).str;
        userdir = userdir.substring(0, userdir.indexOf("\\config"));

        let dbdir = [ userdir, "Msg" ].join("\\");
        console.log("dbdir: " + dbdir);

        return dbkey_20.readByteArray(dbkeyLength);
    },

    patch() {

        Interceptor.attach(symbols.recvmsg(), {
            onEnter: function(args) {
                let message = new recv_context(args[0]);

                console.log("recvmsg: " + "(" + message.type + ") " + message.content.str);

                if (message.content.str.includes("蔡徐坤")) {
                    message.replace("朋友, 这可不兴讲!", 10000);
                }
            }
        });

    },
    unpatch() {
        Interceptor.revert(symbols.recvmsg());
    },

};
