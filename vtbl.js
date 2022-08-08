
/*

    vftable (Alpha)

*/

"use strict";



/* Virtual Table Swap (VTableSwap) */
class vftableHelper {

    #vftable_ptr_ = NULL;
    #vftable_shadow_ = [ NULL, NULL ];

    constructor(instance, limit_count=0) {
        this.#vftable_ptr_ = ptr(instance);

        /* vftable dump */
        this.#vftable_shadow_[0] = this.vftable();
        this.#vftable_shadow_[1] = Memory.dup(
            this.vftable(), 
            Process.pointerSize * this.#vftable_count(limit_count));
    }

    get() { return this.#vftable_ptr_; }

    vftable() {
        return this.get().readPointer();
    }

    replace() {
        this.get().writePointer( this.#vftable_shadow_[1] );
    }

    revert() {
        this.get().writePointer( this.#vftable_shadow_[0] );
        this.#vftable_shadow_[1] = NULL;
    }

    override_vftable_from_ordinal(fndetour, vfidx) {
        let ptablefn = this.vftable().add( vfidx * Process.pointerSize );
        let fnoriginal = ptablefn.readPointer();
        ptablefn.writePointer(fndetour);
        return fnoriginal;
    }

    #has_exec(address) {
        let addr = ptr(address);
        if ( addr.equals(NULL) ) return false;

        /* https://docs.microsoft.com/windows/win32/api/winbase/nf-winbase-isbadcodeptr */
        return 0 == new NativeFunction(
            Module.getExportByName("kernel32.dll", "IsBadCodePtr"), 
            "bool", [ "pointer" ])(addr);
    }

    #vftable_count(limit_count=0) {
        let limit_count_ = limit_count;

        if (0 == limit_count)
            limit_count_ = int64(Process.pageSize / Process.pointerSize);

        let count_ = 0; 
        do {
            let empty_ = this.vftable().add( count_ *  Process.pointerSize ).readPointer();
            /* eof */
            if (!this.#has_exec(empty_)) break;
            count_ += 1;
        } while (count_ < limit_count_);

        return count_;
    }
}
