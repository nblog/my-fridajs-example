
import { addr_transform } from "./aobscan.js";



class stdstring {
    #data = NULL;

    constructor(data=NULL) {
        this.#data = data;
    }

    get length() { return this.#data.add(16).readU32(); }
    set length(value) { 
        this.#data.add(16).writeU32(value);
        this.#data.add(16 + Process.pointerSize).writeU32(value || (value | 15));
    }

    c_str() {
        if (0 === this.length) return "";
        if (16 > this.length) return this.#data.readAnsiString() ?? '';
        return this.#data.readPointer().readAnsiString() ?? '';
    }

    empty() {
        return 0 === this.length;
    }

    clear() {
        this.length = 0; this.#data.writePointer(NULL);
    }
}



let addrhelper = new addr_transform("WeChatWin.dll");

let symbols = {
    userdir: function () {
        /* "makeDataPath assert fail" */
        let match = addrhelper.aobscan("84 C0 74 15 83 3D ?? ?? ?? ?? 00 74 0C B9");
        if (1 === match.length) {
            let buffer = match[0].address.add(13).add(1).readPointer();
            if (buffer.add(Process.pointerSize).readU32()) {
                return buffer.readPointer().readUtf16String() ?? "";
            }
        }
        return "";
    },
    user: function () {
        let userdir = this.userdir();
        return userdir.match(/WeChat Files\\(.*?)\\/)?.[1] ?? "";
    },
    recvmsg: function () {
        /* "InstanceCounter<class AddMsgInfo,1000>::onInstanceCreate" */
        let match = [];
        match = addrhelper.aobscan("6A 01 6A 01 6A 00 6A 00 6A 00 83 EC 48 8B CC 50 E8 ?? ?? ?? ?? 8B CE E8");
        if (1 === match.length) {
            return addrhelper.va(addrhelper.call(match[0].address.add(0x17)));
        }
        match = addrhelper.aobscan("6A 00 6A 00 6A 00 E8 ?? ?? ?? ?? 50 C6 45 FC 02");
        if (1 === match.length) {
            return addrhelper.va(addrhelper.call(match[0].address.add(0x6)));
        }
        return NULL;
    },
    dbkey: function () {
        /*
            PRAGMA hexkey = \'{}\';
            PRAGMA cipher_page_size = 4096;
            PRAGMA kdf_iter = 64000;
            PRAGMA cipher_hmac_algorithm = HMAC_SHA1;
            PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;
        */
        /* "On Set Md5 : %s" */
        let dbkeyOffset = 0;
        {
            let match = addrhelper.aobscan("83 FF 20 75 15 85 F6 74 11 57 56 8D 88");
            dbkeyOffset = addrhelper.imm32(match[0].address.add(0xb).add(2));
        }
        /* "On Set Info info md5 : %s, y : %s" */
        let match = addrhelper.aobscan("83 C4 70 E8 ?? ?? ?? ?? FF 76 0C 8D 4D 08 FF 76 08 FF 76 04 FF 36 51 8B C8");
        let fnAddr = addrhelper.va(addrhelper.call(match[0].address.add(3)));
        let loginMgr = new NativeFunction(fnAddr, 'pointer', [])();
        let dbkeyLength = loginMgr.add(dbkeyOffset).add(Process.pointerSize).readU32();
        let dbkey_20 = loginMgr.add(dbkeyOffset).readPointer().readByteArray(dbkeyLength);
        /* not logged in */
        if (0 === dbkeyLength || null === dbkey_20) {
            return { "userdir": "", "dbkey": new Uint8Array(0) };
        }
        let userdir = loginMgr.add(0x10).readPointer().readUtf16String() ?? "";
        if ("" !== userdir) {
            userdir = userdir.substring(0, userdir.indexOf("config"));
        }
        return { "userdir": userdir, "dbkey": new Uint8Array(dbkey_20) };
        /* phone number */
        // let phone_number = new stdstring(loginMgr.add(0xF0));
    },
    revokemsg: function(allow=true) {
        /* 
            "On RevokeMsg svrId"
            8B CF E8 ?? ?? ?? ?? 83 C4 18 84 C0 0F 84 +0x2 call
        */
        let match = addrhelper.aobscan( "8B CF E8 ?? ?? ?? ?? 83 C4 18 84 C0 0F 84" );

        let fnAddr = addrhelper.va( addrhelper.call( match[0]["address"].add(2) ) ) ;

        if (!allow) {
            Interceptor.replace( fnAddr, new NativeCallback(() => {
                return Number(false);
            }, 'bool', []));
        } else Interceptor.revert( fnAddr );

        return !fnAddr.equals(NULL);
    },
    x64: {
        userdir: function () {
            let match = addrhelper.aobscan("84 C0 74 ?? 48 83 3D ?? ?? ?? ?? 00 74 ?? 48 8D 0D");
            if (1 === match.length) {
                let buffer = addrhelper.mem32(match[0].address.add(14).add(3));
                if (buffer.add(Process.pointerSize).readU32()) {
                    return buffer.readPointer().readUtf16String() ?? "";
                }
            }
            return "";
        },
        user: function () {
            let userdir = this.userdir();
            return userdir.match(/WeChat Files\\(.*?)\\/)?.[1] ?? "";
        },
        recvmsg: function () {
            let match = [];
            match = addrhelper.aobscan("C6 44 24 20 00 45 33 C9 45 33 C0 48 8D 54 24 40 48 8D 4D 30 E8");
            if (1 === match.length) {
                return addrhelper.va(addrhelper.call(match[0].address.add(20)));
            }
            return NULL;
        },
        dbkey: function () {
            let dbkeyOffset = 0;
            {
                let match = addrhelper.aobscan("83 FF 20 75 ?? 48 85 DB 74 ?? 48 8D 8E");
                dbkeyOffset = addrhelper.imm32(match[0].address.add(10).add(3));
            }
            let match = addrhelper.aobscan("B9 02 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4B 18");
            let fnAddr = addrhelper.va(addrhelper.call(match[0].address.add(10)));
            let loginMgr = new NativeFunction(fnAddr, 'pointer', [])();
            let dbkeyLength = loginMgr.add(dbkeyOffset).add(Process.pointerSize).readU32();
            let dbkey_20 = loginMgr.add(dbkeyOffset).readPointer().readByteArray(dbkeyLength);
            /* not logged in */
            if (0 === dbkeyLength || null === dbkey_20) {
                return { "userdir": "", "dbkey": new Uint8Array(0) };
            }
            let userdir = loginMgr.add(0x28).readPointer().readUtf16String() ?? "";
            if ("" !== userdir) {
                userdir = userdir.substring(0, userdir.indexOf("config"));
            }
            return { "userdir": userdir, "dbkey": new Uint8Array(dbkey_20) };
            /* phone number */
            // let phone_number = new stdstring(loginMgr.add(0x128));
        },
        revokemsg: function(allow=true) {
            throw new Error("Not implemented yet");
        },
        view_sendtext: function(user: string, text: string) {

        },
        view_sendscreenshot(user: string, picture: string) {

        },
        view_sendcustomemoji: function(user: string, image: string) {

        },
        view_sendfile(user: string, file: string) {

        },
    }
};



class AddMsgInfo32 {
    #instance = NULL;
    constructor(instance: NativePointer) {
        this.#instance = instance;
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
        49: viewer(file / share / link / money)
        10000: system
    */
    get type() { return this.#instance.add(4 * Process.pointerSize).add(4).readU32(); }
    set type(value) { this.#instance.add(4 * Process.pointerSize).add(4).writeU32(value); }
    get sender() {
        return new stdstring(this.#instance.add(3 * Process.pointerSize).readPointer().add(Process.pointerSize).readPointer());
    }
    get receiver() {
        return new stdstring(this.#instance.add(6 * Process.pointerSize).readPointer().add(Process.pointerSize).readPointer());
    }
    get content() {
        return new stdstring(this.#instance.add(7 * Process.pointerSize).readPointer().add(Process.pointerSize).readPointer());
    }
    skip() {
        this.content.clear(); this.type = 0;
    }
}

class AddMsgInfo64 {
    #instance = NULL;
    constructor(instance: NativePointer) {
        this.#instance = instance;
    }
    get type() { return this.#instance.add(4 * Process.pointerSize).add(4).readU32(); }
    set type(value) { this.#instance.add(4 * Process.pointerSize).add(4).writeU32(value); }
    get sender() {
        return new stdstring(this.#instance.add(3 * Process.pointerSize).readPointer().add(Process.pointerSize).readPointer());
    }
    get receiver() {
        return new stdstring(this.#instance.add(5 * Process.pointerSize).readPointer().add(Process.pointerSize).readPointer());
    }
    get content() {
        return new stdstring(this.#instance.add(6 * Process.pointerSize).readPointer().add(Process.pointerSize).readPointer());
    }
    skip() {
        this.content.clear(); this.type = 0;
    }
}
