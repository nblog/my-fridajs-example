

function size_of_image(addr=NULL) {
    let nt_addr = addr.add(addr.add(0x3C).readU32());
    let nt_header = nt_addr.readU32();
    if (nt_header != 0x4550) return 0;

    let file_addr = nt_addr.add(0x4);
    let file_header = file_addr.readByteArray(0x14);

    let opt_addr = file_addr.add(0x14);
    let opt_header = opt_addr.readByteArray(0x60);

    let range_length = function(addr) {
        for (const range of Process.enumerateRanges('r--')) {
            if (range.base.equals(addr)) {
                return range.size;
            }
        };
        return 0;
    }

    return Math.max(opt_addr.add(0x38).readU32(), range_length(addr));
}


rpc.exports.scan = function (dumpdir='') {
    for (const range of Process.enumerateRanges('r--')) {
        /* 'This program cannot be run in DOS mode' */
        try {
            let dosstub = '54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F 64 65';
            let match = Memory.scanSync(range.base, range.size, dosstub);

            if (match.length === 0) continue;

            for (let index = 0; index < match.length; index++) {
                let addr = match[index].address.sub(78);
                let length = size_of_image(addr);
                if (length === 0) continue;

                if (!match[index].address.and(255).equals(78)) {
                    console.log(`embedded: [${length.toString(16)}]  ${addr}`);

                    if (dumpdir.length > 1) {
                        new File(`${dumpdir}/PRV-${addr.toString(16)}.mem`, "wb").write(addr.readByteArray(length));
                    }
                }
                else if (Process.findModuleByAddress(addr) === null) {
                    console.log(`mapping: [${length.toString(16)}]  ${addr}`);

                    if (dumpdir.length > 1) {
                        new File(`${dumpdir}/MAP-${addr.toString(16)}.mem`, "wb").write(addr.readByteArray(length));
                    }
                }
            }
        } catch (error) { continue; }
    }
}
