
rpc.exports.scan = function () {
    for (const range of Process.enumerateRanges('r--')) {
        /* 'This program cannot be run in DOS mode' */
        try {
            let dosstub = '54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F 64 65';
            let match = Memory.scanSync(range.base, range.size, dosstub);

            if (match.length === 0) continue;

            for (let index = 0; index < match.length; index++) {
                let addr = match[index].address.sub(78);

                if (match[index].address.and(255).equals(78)) {
                    if (Process.findModuleByAddress(addr) === null)
                        console.log(`mapping: [${0}]  ${addr}`);
                }
                else {
                    console.log(`embedded: [${0}]  ${addr}`);
                }
            }
        } catch (error) { continue; }
    }
}