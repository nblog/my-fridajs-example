

export class addr_transform {

    #moduleName = ''

    constructor(moduleName: string='') {
        this.#moduleName = moduleName || Process.enumerateModules()[0].name;
    };

    module() { return Process.getModuleByName(this.#moduleName); };

    base() { return this.module().base; };

    va(rva: number) { return this.base().add(rva); };

    rva(va: NativePointer) { return Number(va.sub(this.base()).and(0x7fffffff)); };

    imm8(addr: NativePointer) { return addr.readS8(); };

    imm16(addr: NativePointer) { return addr.readS16(); };

    imm32(addr: NativePointer) { return addr.readS32(); };

    imm64(addr: NativePointer) { return addr.readS64(); }

    mem32(addr) { return this.rva(addr.add(this.imm32(addr)).add(4)); };

    call(addr) { return this.mem32(addr.add(1)); };

    equal(addr: NativePointer, cmd='call') {
        let info = Instruction.parse(addr);
        return [ info.mnemonic, info.opStr ].join(' ').includes(cmd.toLowerCase());
    };

    aobscan(pattern: string) {
        for (const m of this.module().enumerateRanges('--x')) {
            let match = Memory.scanSync(m.base, m.size, pattern);
            if (0 < match.length) return match;
        }
        return [];
    };
}
