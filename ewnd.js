
/*

    reference: https://github.com/fjqisba/E-Debug
    易语言窗口枚举 (Beta)

*/


function ewnds() {

    var aobinfo = {
        notes: "enumerate window info",
        m: Process.enumerateModules()[0],
        search: "8B 44 24 0C 8B 4C 24 08 8B 54 24 04 50 51 52 B9",
    }

    const retValue = Memory.scanSync(aobinfo.m.base, aobinfo.m.size, aobinfo.search);

    if (0 < retValue.length) {
        if (1 == retValue.length) {
            return ptr(retValue[0].address);
        }
    }

    return NULL;
}


function eload() {

    var aobinfo = {
        notes: "loader window",
        m: Process.enumerateModules()[0],
        search: "83 EC 0C 33 C0 56 8B 74 24 1C 57 8B 7C 24 18 C7 07 00 00 00 00 8B 4E 14 85 C9 74 13 50 8B 46 0C 50 68 D6 07 00 00",
    }

    const retValue = Memory.scanSync(aobinfo.m.base, aobinfo.m.size, aobinfo.search);

    if (0 < retValue.length) {
        if (1 == retValue.length) {
            return ptr(retValue[0].address);
        }
    }

    return NULL;
}


const retAddres = {
    "ewnds": ewnds(),
    "eload": eload(),
};

if (NULL == retAddres.ewnds || NULL == retAddres.eload) {
    throw ReferenceError("refers to an invalid address");
}



rpc.exports = {

    getWndIds: function() {

        const infosPtr = retAddres.ewnds.add(16).readPointer();

        const count = Number(infosPtr.add(284).readPointer()) >> 3;

        const wndArr = infosPtr.add(276).readPointer();

        var ids = new Uint32Array(count)

        for (let index = 0; index < count; index++) {
            ids[index] = wndArr.add(index * 4).readU32();
        }

        return ids;
    },

    loadEwnd: function(id) {

        var fnPtr = Memory.alloc(
            Process.pageSize
        );

        Memory.patchCode(fnPtr, Process.pageSize, code => {
            const cw = new X86Writer(code, { pc: fnPtr });
            cw.putPushReg('ebp');
            cw.putMovRegReg('ebp', 'esp');
            cw.putPushU32(0x80000002);
            cw.putPushU32(0x0);
            cw.putPushU32(0x1);
            cw.putPushU32(0x0);
            cw.putPushU32(0x0);
            cw.putPushU32(0x0);
            cw.putPushU32(0x10001);
            cw.putPushU32(0x6010002);
            cw.putPushU32(id);
            cw.putPushU32(0x3);
            cw.putMovRegAddress('ebx', retAddres.eload);
            cw.putCallNearLabel('c1');
            cw.putAddRegImm('esp', 0x28);
            cw.putLeave();
            cw.putRet();
            cw.putLabel('c1');
            cw.putLeaRegRegOffset('eax', 'esp', 0x8);
            cw.putSubRegImm('esp', 0xC);
            cw.putPushReg('eax');
            cw.putBytes([0xFF, 0x74, 0x24, 0x14,]); // push [esp+0x14]
            cw.putXorRegReg('eax', 'eax');
            cw.putMovRegOffsetPtrReg('esp', 0x8, 'eax');
            cw.putMovRegOffsetPtrReg('esp', 0xC, 'eax');
            cw.putMovRegOffsetPtrReg('esp', 0x10, 'eax');
            cw.putLeaRegRegOffset('edx', 'esp', 0x8);
            cw.putPushReg('edx');
            cw.putCallReg('ebx');
            cw.putMovRegRegOffsetPtr('eax', 'esp', 0xC);
            cw.putMovRegRegOffsetPtr('edx', 'esp', 0x10);
            cw.putMovRegRegOffsetPtr('ecx', 'esp', 0x14);
            cw.putAddRegImm('esp', 0x18);
            cw.putRetImm(4);
            cw.flush();
        });

        return new NativeFunction(fnPtr, "pointer", [])();
    },
    
};