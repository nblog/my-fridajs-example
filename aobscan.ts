
export class addr_transform {
    #version = 'unknown'
    #moduleName = ''

    constructor(moduleName: string='', version: string='') {
        this.#version = version;
        this.#moduleName = moduleName || Process.enumerateModules()[0].name;
    };

    module() { return Process.getModuleByName(this.#moduleName); };

    base() { return this.module().base; };

    va(rva: number) { return this.base().add(rva); };

    rva(va: NativePointer) { return va.sub(this.base()).toUInt32(); };

    /** little-endian 128-bit integer from ArrayBuffer */
    private toInt128(arr: ArrayBuffer | null) {
        if (!arr || arr.byteLength < 16) {
            throw new Error(`toInt128: invalid buffer (got ${arr?.byteLength ?? 'null'})`);
        }
        const view = new DataView(arr);
        const lo = view.getBigUint64(0, true);
        const hi = view.getBigUint64(8, true);
        return (hi << 64n) | lo;
    };

    /** read unsigned immediate: number (8/16/32), UInt64 (64), bigint (128) */
    imm8(addr: NativePointer, immOffset: number=0) { return addr.add(immOffset).readU8(); };
    imm16(addr: NativePointer, immOffset: number=0) { return addr.add(immOffset).readU16(); };
    imm32(addr: NativePointer, immOffset: number=0) { return addr.add(immOffset).readU32(); };
    imm64(addr: NativePointer, immOffset: number=0) { return addr.add(immOffset).readU64(); };
    imm128(addr: NativePointer, immOffset: number=0) { return this.toInt128(addr.add(immOffset).readByteArray(16)); };

    /** dereference pointer at addr, then read value. throws on NULL pointer. */
    deref8(addr: NativePointer) { return this.#derefSafe(addr).readU8(); };
    deref16(addr: NativePointer) { return this.#derefSafe(addr).readU16(); };
    deref32(addr: NativePointer) { return this.#derefSafe(addr).readU32(); };
    deref64(addr: NativePointer) { return this.#derefSafe(addr).readU64(); };
    deref128(addr: NativePointer) { return this.toInt128(this.#derefSafe(addr).readByteArray(16)); };

    #derefSafe(addr: NativePointer): NativePointer {
        const p = addr.readPointer();
        if (p.isNull()) {
            throw new Error(`deref: NULL pointer at ${addr}`);
        }
        return p;
    };

    /** x86 rel32 resolve: addr points to the 4-byte displacement field, returns RVA of target.
     *  target = addr + 4 (field size) + *addr (signed displacement) */
    rel32(addr: NativePointer) { return this.rva(addr.add(4).add(addr.readS32())); };

    /** resolve CALL/JMP rel32 target from instruction start (single-byte opcode: E8/E9).
     *  NOT suitable for 2-byte opcodes (e.g. 0F 8x, FF 15). */
    rel32CallTarget(addr: NativePointer) { return this.rel32(addr.add(1)); };

    /** scan module memory for byte pattern. protection filter defaults to executable ('--x'). */
    aobscan(pattern: string, protection: string='--x') {
        const matches = [];
        for (const m of this.module().enumerateRanges(protection)) {
            matches.push(...Memory.scanSync(m.base, m.size, pattern));
        }
        return matches;
    };
}
