function mmlfg(seed) {
    let i = 14
    let j = 12
    let s = new Array(15).fill(0)

    seed = BigInt(seed)
    for (let i = 0; i < 15; i++) {
        seed *= 0x3243f6a8885a308dn
        seed += 1111111111111111111n
        seed &= 0xffffffffffffffffn
        s[i] = seed ^ seed>>31n | 1n
    }

    return function() {
        let r = s[i] * s[j]
        s[i] = r & 0xffffffffffffffffn
        i = (i + 14) % 15
        j = (j + 14) % 15
        return (r >> 32n) & 0xffffffffffffffffn
    }
}


// Example
let g = [mmlfg(0), mmlfg(1), mmlfg(2), mmlfg(3)]
for (let i = 0; i < 40; i++) {
    function f(x) { return ("0000000000000000" + x.toString(16)).slice(-16) }
    console.log(f(g[0]()), f(g[1]()), f(g[2]()), f(g[3]()))
}
