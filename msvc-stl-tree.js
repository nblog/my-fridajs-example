///<reference path='C:/Users/r0th3r/OneDrive/Code/index.d.ts'/>

/**
 * MSVC STL container readers for Frida
 *
 * Provides read-only wrappers for MSVC-compiled C++ STL containers:
 *   - StdTree / StdTreeNode: std::map / std::set (std::_Tree)
 *
 * Usage:
 *   // 1) Include this file in your agent (single-file script style):
 *   //    Simply paste/append the classes you need, or concatenate scripts.
 *   //
 *   // 2) From a head node pointer:
 *   const tree = new StdTree(ptr('0x...'));
 *   tree.dump();
 *   const ptrs = tree.values();          // NativePointer[] to _Myval
 *
 *   // 3) From the std::map/std::set object itself:
 *   const tree = StdTree.fromTreeObject(objPtr);
 *
 *   // 4) Combine with StdString to read string keys/values:
 *   tree.values(n => new StdString(n.data()).read());
 *
 *   // 5) map<K,V> pair layout: K at data()+0x00, V after K (aligned)
 *   tree.values(n => {
 *       const key = new StdString(n.data()).read();
 *       const val = n.data().add(32).readPointer(); // adjust offset to V
 *       return { key, val };
 *   });
 */

// ---------------------------------------------------------------------------
// Logging (self-contained fallback, does not override host log)
// ---------------------------------------------------------------------------
const _msvcStlLog = function (tag, ...args) {
    if (typeof globalThis.log === 'function') {
        globalThis.log(tag, ...args);
        return;
    }
    const tid = Process.getCurrentThreadId();
    const ts = new Date().toISOString().slice(11, 19); // HH:mm:ss
    console.log(`[frida][${ts}] ${tag}:`, ...args);
};

// ---------------------------------------------------------------------------
// StdTree - MSVC std::_Tree (std::map / std::set) node reader & traversal
// ---------------------------------------------------------------------------
/**
 * MSVC _Tree_node layout (x64):
 *   +0x00  _Left    (head: leftmost node  / node: left child)
 *   +0x08  _Parent  (head: root node      / node: parent)
 *   +0x10  _Right   (head: rightmost node / node: right child)
 *   +0x18  _Color   (0 = red, 1 = black)
 *   +0x19  _Isnil   (1 = sentinel head node, 0 = real node)
 *   +0x20  _Myval   (set<T>: T;  map<K,V>: pair<const K, V>)
 *
 * The sentinel head node (_Isnil == 1) is allocated by the std::_Tree object.
 * For a non-empty tree its _Left/_Parent/_Right point at the first/root/last
 * real nodes; for an empty tree all three point back at the head itself.
 */
class StdTreeNode {
    constructor(ptr) {
        this._ptr = ptr;
    }

    get left() {
        return this._ptr.readPointer();
    }

    get parent() {
        return this._ptr.add(8).readPointer();
    }

    get right() {
        return this._ptr.add(16).readPointer();
    }

    /** 0 = red, 1 = black */
    get color() {
        return this._ptr.add(24).readU8();
    }

    get colorName() {
        return this.color === 0 ? 'red' : 'black';
    }

    /** true for the sentinel head node (not a real element) */
    get isNil() {
        return this._ptr.add(25).readU8() !== 0;
    }

    /**
     * Pointer to the stored value (_Myval at +0x20).
     * Interpretation depends on the container's value_type:
     *   set<T>    → T
     *   map<K,V>  → pair<const K, V>  (K at +0x00, V after K, aligned)
     */
    data() {
        return this._ptr.add(32);
    }

    toString() {
        const tag = this.isNil ? 'head' : this.colorName;
        return `StdTreeNode(${this._ptr}, ${tag})`;
    }
}

/**
 * In-order (sorted) traversal over a MSVC std::_Tree.
 * Construct with the sentinel head node address, or use fromTreeObject()
 * with the std::map/std::set object address.
 */
class StdTree {
    /** @param {NativePointer} headPtr - address of the _Isnil==1 head node */
    constructor(headPtr) {
        this._head = new StdTreeNode(headPtr);
    }

    /**
     * Build from the std::_Tree (std::map/std::set) object itself.
     * MSVC x64 object layout: +0x00 = _Myhead, +0x08 = _Mysize.
     * @param {NativePointer} treePtr
     */
    static fromTreeObject(treePtr) {
        return new StdTree(treePtr.readPointer());
    }

    get head() {
        return this._head;
    }

    get isEmpty() {
        return this._head.left.equals(this._head._ptr);
    }

    /** First (minimum) node pointer; equals head when the tree is empty */
    get first() {
        return this._head.left;
    }

    /** Last (maximum) node pointer; equals head when the tree is empty */
    get last() {
        return this._head.right;
    }

    /** Root node pointer; equals head when the tree is empty */
    get root() {
        return this._head.parent;
    }

    /**
     * All real nodes in sorted order. Aborts early on corrupt pointers
     * or when maxNodes is exceeded, returning whatever was collected.
     * @param {number} [maxNodes=100000] safety cap
     * @returns {StdTreeNode[]}
     */
    nodes(maxNodes) {
        maxNodes = maxNodes || 100000;
        const out = [];
        try {
            let node = new StdTreeNode(this.first);
            while (!node.isNil && out.length < maxNodes) {
                out.push(node);
                // in-order successor
                const right = new StdTreeNode(node.right);
                if (!right.isNil) {
                    node = right;
                    let next = new StdTreeNode(node.left);
                    while (!next.isNil) {
                        node = next;
                        next = new StdTreeNode(node.left);
                    }
                } else {
                    let parent = new StdTreeNode(node.parent);
                    while (!parent.isNil && node._ptr.equals(parent.right)) {
                        node = parent;
                        parent = new StdTreeNode(parent.parent);
                    }
                    node = parent;
                }
            }
        } catch (e) {
            _msvcStlLog('stdtree', `walk aborted after ${out.length} nodes: ${e.message}`);
        }
        if (out.length >= maxNodes) {
            _msvcStlLog('stdtree', `walk hit maxNodes cap (${maxNodes}) - tree may be corrupt`);
        }
        return out;
    }

    /**
     * Value pointers (_Myval) of all nodes, in sorted order.
     * @param {function(StdTreeNode): *} [read] optional per-node reader;
     *        defaults to returning the raw data() pointer
     * @returns {Array}
     */
    values(read) {
        read = read || function (node) { return node.data(); };
        return this.nodes().map(function (node) { return read(node); });
    }

    /**
     * Log one line per node with structure info.
     * @param {function(StdTreeNode): string} [read] optional value formatter
     */
    dump(read) {
        const nodes = this.nodes();
        _msvcStlLog('stdtree', `head=${this._head._ptr} empty=${this.isEmpty} count=${nodes.length}`);
        nodes.forEach(function (node, i) {
            let extra = '';
            if (read) {
                try {
                    extra = ' value=' + read(node);
                } catch (e) {
                    extra = ` value=<read error: ${e.message}>`;
                }
            }
            _msvcStlLog('stdtree', `#${i} ${node.colorName} node=${node._ptr}` +
                ` left=${node.left} parent=${node.parent} right=${node.right}` +
                ` data=${node.data()}${extra}`);
        });
    }
}
