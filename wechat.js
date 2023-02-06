///<reference path='C:\\Users\\r0th3r\\OneDrive\\Codes\\index.d.ts'/>





let addr_transform = {

    base: function(name="WeChatWin.dll") { 
        return Process.getModuleByName(name).base; 
    },

    va: function(addr) { return this.base().add(addr); },

    rva: function(addr) { return ptr(addr).sub(this.base()); },

    imm8: function(addr) { return ptr(addr).readU8(); },

    imm16: function(addr) { return ptr(addr).readU16(); },

    imm32: function(addr) { return ptr(addr).readU32(); },

    mem: function(addr) {
        let absValue = addr_transform.imm32(addr);
        return 4 == ptrlength ? absValue : 
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
        Process.enumerateRanges("--x").forEach(function(range) {
            Memory.scanSync(range.base, range.size, pattern).forEach(function(match) {
                matches.push(match);
            });
        });
        return matches;
    }
}



let symbols = {
    toVa: function (rva=NULL) {
        return addr_transform.va(rva);
    },

    dbkey: function() {
        /*
            "On Set Info info md5 : %s, y : %s"
            B9 02 00 00 00 68 ?? ?? ?? ?? 68 97 01 00 00 C6 00 03 E8 +0x1a call
        */
        let dbkeyOffset = 0x464;

        let match = addr_transform.aobscan( "B9 02 00 00 00 68 ?? ?? ?? ?? 68 97 01 00 00 C6 00 03 E8" );

        let fnAddr = this.toVa( addr_transform.call( match[0]["address"].add(0x1a) ) );

        let loginMgr = new NativeFunction( fnAddr, 'pointer', [], 'mscdecl')();

        let dbkey_20 = loginMgr.add(dbkeyOffset).readPointer();

        if (dbkey_20.isNull()) { return null; }

        let dbkeyLength = loginMgr.add(dbkeyOffset).add(Process.pointerSize).readU32();

        return dbkey_20.readByteArray(dbkeyLength);
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

    /* 3.8.1.26 */
    sendmsg: function() {
        /* TEXT IMAGE NETEMOJI EXT */
        return this.toVa( 0xB6A930 );
    },
    recvmsg: function() {
        return this.toVa( addr_transform.call( addr_transform.base().add(0xB996DA) ) ) ;
    }
}



class wx_string {
    constructor(data) {
        this._data = ptr(data)
    }

    get length() {
        return this._data.add(0x4).readU32();
    }

    get str() {
        if ( 1 > this.length ) return "";
        return String( this._data.readPointer().readUtf16String() );
    }

    empty() {
        return 0 == this.length;
    }

    clear() {
        if ( this.empty() ) return;
        this._data.add(0x4).writeU32(0);
        this._data.add(0x8).writeU32(0);
        this._data.readPointer().writeU16(0);
    }
}

class recv_context {
    constructor(pcontext) {
        this._msg_type = pcontext.add(0x38);
        this._msg_self = pcontext.add(0x3C);
        this._msg_sender = new wx_string(pcontext.add(0x48));
        this._msg_content = new wx_string(pcontext.add(0x70));
    }

    /*
        1: text
        3: image
        34: voice
        43: video
        48: location
        49: share
        10000: system
    */
    get msg_type() {
        return Number(this._msg_type.readU32());
    }

    get msg_self() {
        return this._msg_self.readU8() == 1;
    }

    get msg_sender() {
        return this._msg_sender.str;
    }

    get msg_content() {
        return this._msg_content.str;
    }

    skip() {
        this._msg_type.writeU32(0); this._msg_content.clear();
    }
}




rpc.exports = {

    patch() {


        // Interceptor.attach(symbols.recvmsg(), {
        //     onEnter: function(args) {
        //         let message = new recv_context(args[0]);

        //         console.log("msg_type: " + message.msg_type);
        //         console.log("msg_self: " + message.msg_self);
        //         console.log("msg_sender: " + message.msg_sender);
        //         console.log("msg_content: " + message.msg_content);

        //         if (message.msg_content.includes("蔡徐坤")) {
        //             message.skip();
        //         }
        //     }
        // });


        // Interceptor.attach(symbols.sendmsg(), {
        //     onEnter: function(args) {
        //         let msg_sender = new wx_string(this.context.edx);
        //         let msg_content = new wx_string(args[0]);

        //         if ( msg_content.str.includes("iKun") ) {
        //             msg_content.clear();
        //         }
        //     }
        // });

    },
    unpatch() {

    }

  };
