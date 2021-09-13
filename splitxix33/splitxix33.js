// splitxix33: a splitmix64 with memorable constants
// This is free and unencumbered software released into the public domain.
function splitxix33(seed) {
    let s = BigInt(seed)
    return function() {
        s += 1111111111111111111n; s &= 0xffffffffffffffffn
        let r = s ^ s>>33n;
        r *= 1111111111111111111n; r &= 0xffffffffffffffffn; r ^= r >> 33n
        r *= 1111111111111111111n; r &= 0xffffffffffffffffn; r ^= r >> 33n
        return r
    }
}

let g = [splitxix33(0), splitxix33(1), splitxix33(2), splitxix33(3)]
for (let i = 0; i < 40; i++) {
    function f(x) { return ("0000000000000000" + x.toString(16)).slice(-16) }
    console.log(f(g[0]()), f(g[1]()), f(g[2]()), f(g[3]()))
}
