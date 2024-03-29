
/*

    vftable (Alpha)

*/

"use strict";




/* Virtual Table Swap (VTableSwap) */
class vftableHelper {

    #vftable_ptr_ = NULL;
    #vftable_shadow_ = [ NULL, NULL ];

    constructor(interfaces, limit_count=-1) {
        this.#vftable_ptr_ = interfaces;

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

    #vftable_count(limit_count) {
        let limit_count_ = 0 > limit_count ? 
        Math.floor(Process.pageSize / Process.pointerSize) : limit_count;

        let count_ = 0;
        for ( ; count_ < limit_count_; count_++) {
            let empty_ = this.vftable().add( count_ *  Process.pointerSize ).readPointer();
            /* eof */
            if (!this.#has_exec(empty_)) break;
        }
        return count_;
    }

    #has_exec(addr) {
        if ( addr.equals(NULL) ) return false;

        /* frida >= 16.2.0 */
        return Memory.queryProtection(addr).endsWith('x');
    }
}
