
/*

    vftable (Alpha)

*/

"use strict";



/* Virtual Table Swap (VTableSwap) */
class vftableHelper {

    #vftable_shadow_ = [ NULL, NULL ];

    constructor(instance) {
        this.this_ptr_ = ptr(instance);

        /* vftable dump */
        this.#vftable_shadow_[0] = this.vftable();
        this.#vftable_shadow_[1] = Memory.dup(
            this.vftable(), 
            Process.pointerSize * this.#vftable_count());
    }

    get() { return this.this_ptr_; }

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
        let ptablefn = this.vftable().add( vfidx * Process.pageSize );
        let fnoriginal = ptablefn.readPointer();
        ptablefn.writePointer(fndetour);
        return fnoriginal;
    }

    #vftable_count(limit_count=0) {
        let limit_count_ = limit_count;

        if (0 == limit_count)
            limit_count_ = int64(Process.pageSize / Process.pointerSize);

        let count_ = 0; 
        do {
            let empty_ = this.vftable().add( count_ *  Process.pointerSize).readPointer();
            /* eof */
            if (empty_.isNull() || null == Process.findRangeByAddress(empty_)) break;
            count_ += 1;
        } while (count_ < limit_count_);

        return count_;
    }
}
