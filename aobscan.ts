

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

    toInt128(arr: ArrayBuffer | null) {
        const view = new DataView(arr!);
        // little-endian 64-bit
        const lo = view.getBigUint64(0, true);
        const hi = view.getBigUint64(8, true);
        return (hi << 64n) | lo;
    };

    imm8(addr: NativePointer, immOffset: number=0) { return addr.add(immOffset).readU8(); };

    imm16(addr: NativePointer, immOffset: number=0) { return addr.add(immOffset).readU16(); };

    imm32(addr: NativePointer, immOffset: number=0) { return addr.add(immOffset).readU32(); };

    imm64(addr: NativePointer, immOffset: number=0) { return addr.add(immOffset).readU64(); };

    imm128(addr: NativePointer, immOffset: number=0) { return this.toInt128(addr.add(immOffset).readByteArray(16)); };

    deref8(addr: NativePointer) { return addr.readPointer().readU8(); };

    deref16(addr: NativePointer) { return addr.readPointer().readU16(); };

    deref32(addr: NativePointer) { return addr.readPointer().readU32(); };

    deref64(addr: NativePointer) { return addr.readPointer().readU64(); };

    deref128(addr: NativePointer) { return this.toInt128(addr.readPointer().readByteArray(16)); };

    /*branch*/
    rel32(addr: NativePointer) { return this.rva(addr.add(addr.readS32()).add(4)); };
    rel32CallTarget(addr: NativePointer) { return this.rel32(addr.add(1)); };

    aobscan(pattern: string) {
        const matches = [];
        for (const m of this.module().enumerateRanges('--x')) {
            matches.push(...Memory.scanSync(m.base, m.size, pattern));
        }
        return matches;
    };
}
