



export class addr_transform {

    #moduleName:string = Process.enumerateModules()[0].name;

    constructor(moduleName:string="") {
        if (moduleName.length) this.#moduleName = moduleName;
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


    mem(addr: NativePointer) {
        let absValue = this.imm32(addr);
        return 4 == Process.pointerSize ? absValue : 
        ( this.rva(addr) + absValue + 4 );
    };

    call(addr: NativePointer) {
        let absValue = this.rva(addr) + this.imm32( addr.add(1) ) + 5;
        return ( absValue & 0xffffffff );
    };

    equal(addr: NativePointer, cmd="call") {
        let info = Instruction.parse( addr );
        return [ info.mnemonic, info.opStr ].join(" ").startsWith( cmd.toLowerCase() );
    };

    aobscan(pattern: string) {
        let matches: MemoryScanMatch[] = [];
        this.module().enumerateRanges("--x").forEach(function(range) {
            Memory.scanSync(range.base, range.size, pattern).forEach(function(match) {
                matches.push(match);
            });
        });
        return matches;
    };
}
