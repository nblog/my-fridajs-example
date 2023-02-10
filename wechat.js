///<reference path='C:\\Users\\r0th3r\\OneDrive\\Codes\\index.d.ts'/>


let addr_transform = {

    moduleName: "WeChatWin.dll",

    module: function() {
        return Process.getModuleByName(this.moduleName);
    },

    base: function() { return this.module().base; },

    va: function(addr) { return this.base().add(addr); },

    rva: function(addr) { return ptr(addr).sub(this.base()); },

    imm8: function(addr) { return ptr(addr).readU8(); },

    imm16: function(addr) { return ptr(addr).readU16(); },

    imm32: function(addr) { return ptr(addr).readU32(); },

    mem: function(addr) {
        let absValue = addr_transform.imm32(addr);
        return 4 == Process.pointerSize ? absValue : 
            Number( addr_transform.rva(addr).add(absValue).add(4) );
    },

    call: function(addr) {
        let absValue = addr_transform.rva(addr).add(
            addr_transform.imm32( addr.add(1) )
        ).add(5) ;
        return Number(absValue) & 0xffffffff;
    },


    aobscan: function(pattern) {
        let matches = [];
        this.module().enumerateRanges("--x").forEach(function(range) {
            Memory.scanSync(range.base, range.size, pattern).forEach(function(match) {
                matches.push(match);
            });
        });
        return matches;
    },

    equal: function(addr, cmd="call") {
        let info = Instruction.parse( ptr(addr) );
        return [ info.mnemonic, info.opStr ].join(" ").includes( cmd.toLowerCase() );
    }
}



/*



*/

let symbols = {
    toVa: function (rva=NULL) {
        return addr_transform.va(rva);
    },

    revokemsg: function(allow=true) {
        /* 
            "On RevokeMsg svrId"
            8B CF E8 ?? ?? ?? ?? 83 C4 18 84 C0 0F 84 +0x2 call
        */
        let match = addr_transform.aobscan( "8B CF E8 ?? ?? ?? ?? 83 C4 18 84 C0 0F 84" );

        let fnAddr = this.toVa( addr_transform.call( match[0]["address"].add(2) ) ) ;

        if (!allow) {
            Interceptor.replace( fnAddr, new NativeCallback(() => {
                return false;
            }, 'bool', []));
        } else Interceptor.revert( fnAddr );

        return fnAddr;
    },
    recvmsg: function() {
        /*
            "receive a unknown msg type: %d"
            E8 ?? ?? ?? ?? 83 C0 01 83 D2 00 52 50 E8 -0xA call
        */
        let match = addr_transform.aobscan( "E8 ?? ?? ?? ?? 83 C0 01 83 D2 00 52 50 E8" );

        let fnAddr = this.toVa( addr_transform.call( match[0]["address"].sub(0xa) ) ) ;

        return fnAddr;
    },

    /* 3.8.1.26 */
    wx_free: function(mem=NULL) {
        return new NativeFunction( 
            this.toVa( 0x21DE211 ), 
            'void', ['pointer'], 'stdcall')( mem );
    },
    wx_malloc: function(length=0) {
        return new NativeFunction( 
            this.toVa( 0x217AC91 ), 
            'pointer', ['size_t'], 'stdcall')( length );
    },
    view_sendtext: function(user, text) {
        let fnAddr = this.toVa( 0xB6A930 );
        let wx = new NativeFunction( fnAddr, 
            'void', ['pointer', 
            'pointer', 'pointer', 'pointer', 'uint', 'bool', 'uint'], 'fastcall');

        let wx_at = wx_string.alloc(); wx_at.str = "";  /* notify@all */
        let wx_user = wx_string.alloc(); wx_user.str = user;
        let wx_text = wx_string.alloc(); wx_text.str = text;

        wx( Memory.alloc(0x2a8), wx_user.data, wx_text.data, wx_at.data, 1, 0, 0 );
    },
    view_sendscreenshot(user, picture) {
        let env = new NativeFunction( this.toVa( 0x65B2A0 ), 'pointer', [], 'mscdecl')( );

        let fnAddr = this.toVa( 0xB6A3F0 );
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
    view_sendfile: function(user, file) {
        let env = new NativeFunction( this.toVa( 0x65DF50 ), 'pointer', [], 'mscdecl')( );

        let fnAddr = this.toVa( 0xA10190 );
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
    view_sendcustomemoji: function(user, image) {
        let env = new NativeFunction( this.toVa( 0x69A7D0 ), 'pointer', [], 'mscdecl')( );

        let fnAddr = this.toVa( 0xAA9FD0 );
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
}



class wx_string {
    #data = NULL; #c_str = NULL;

    constructor(data) {
        this.#data = data;
    }

    get data() { return this.#data; }
    set data(value) { this.#data = value; }
    get buffer() { return this.empty() ? NULL : this.data.readPointer(); }
    set buffer(value) { if (!this.data.isNull()) this.data.writePointer(value); }

    get length() { return this.data.add(0x4).readU32(); }
    set length(value) { 
        this.data.add(0x4).writeU32(value);
        this.data.add(0x8).writeU32(value);
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

    constructor(pcontext) {
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
}




rpc.exports = {
    dbkey: function() {
        /*
            "On Set Info info md5 : %s, y : %s"
            83 C4 70 E8 ?? ?? ?? ?? FF 76 0C 8D 4D 08 FF 76 08 FF 76 04 FF 36 51 8B C8 +3 call
        */
        let dbkeyOffset = 0x464;

        let match = addr_transform.aobscan( "83 C4 70 E8 ?? ?? ?? ?? FF 76 0C 8D 4D 08 FF 76 08 FF 76 04 FF 36 51 8B C8" );

        let fnAddr = addr_transform.va( addr_transform.call( match[0]["address"].add(3) ) );

        let loginMgr = new NativeFunction( fnAddr, 'pointer', [], 'mscdecl')();

        let dbkey_20 = loginMgr.add(dbkeyOffset).readPointer();

        /* not logged in */
        if (dbkey_20.isNull()) { return null; }

        let dbkeyLength = loginMgr.add(dbkeyOffset).add(Process.pointerSize).readU32();
        /*
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

                if (message.content.str.includes("蔡徐坤")) {
                    message.skip();
                }
            }
        });

    },
    unpatch() {

    }

  };
