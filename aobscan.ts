

export class addr_transform {

    #moduleName = ""

    constructor(moduleName: string) {
        this.#moduleName = moduleName ?? Process.enumerateModules()[0].name;
    };

    module() {
        return Process.getModuleByName(this.#moduleName);
    };

    base() { return this.module().base; };

    va(rva: number) { return this.base().add(rva); };

    rva(va: NativePointer) { return Number( va.sub(this.base()).and(0xffffffff) ); };

    imm8(addr: NativePointer) { return addr.readU8(); };

    imm32(addr: NativePointer) { return addr.readU32(); };

    imm64(addr: NativePointer) { return addr.readU64(); }


    call(addr: NativePointer) {
        let absValue = this.rva(addr) + this.imm32( addr.add(1) ) + 5;
        return ( absValue & 0xffffffff );
    };

    equal(addr: NativePointer, cmd="call") {
        let info = Instruction.parse( addr );
        return [ info.mnemonic, info.opStr ].join(" ").includes( cmd.toLowerCase() );
    };

    aobscan(pattern: string) {
        for (const m of this.module().enumerateRanges("--x")) {
            let match = Memory.scanSync(m.base, m.size, pattern);
            if (0 < match.length) return match;
        }
        return [];
    };
}
