/* This is free and unencumbered software released into the public domain. */

/**
 * Generate and return a new UUID. This function makes no allocations
 * except for the returned string.
 */
let UUID = (function() {
    const HEX = '0123456789abcdef'.split(/(?:)/);
    const VER = '89ab'.split(/(?:)/);
    const out = '........-....-4...-v...-............'.split(/(?:)/);
    const raw = new Uint8Array(16);
    return function UUID() {
        window.crypto.getRandomValues(raw);
        out[ 0] = HEX[raw[ 0] >> 4];
        out[ 1] = HEX[raw[ 0] & 15];
        out[ 2] = HEX[raw[ 1] >> 4];
        out[ 3] = HEX[raw[ 1] & 15];
        out[ 4] = HEX[raw[ 2] >> 4];
        out[ 5] = HEX[raw[ 2] & 15];
        out[ 6] = HEX[raw[ 3] >> 4];
        out[ 7] = HEX[raw[ 3] & 15];
        out[ 9] = HEX[raw[ 4] >> 4];
        out[10] = HEX[raw[ 4] & 15];
        out[11] = HEX[raw[ 5] >> 4];
        out[12] = HEX[raw[ 5] & 15];
        out[15] = HEX[raw[ 6] & 15];
        out[16] = HEX[raw[ 7] >> 4];
        out[17] = HEX[raw[ 7] & 15];
        out[19] = VER[raw[ 8] &  3];
        out[20] = HEX[raw[ 8] & 15];
        out[21] = HEX[raw[ 9] >> 4];
        out[22] = HEX[raw[ 9] & 15];
        out[24] = HEX[raw[10] >> 4];
        out[25] = HEX[raw[10] & 15];
        out[26] = HEX[raw[11] >> 4];
        out[27] = HEX[raw[11] & 15];
        out[28] = HEX[raw[12] >> 4];
        out[29] = HEX[raw[12] & 15];
        out[30] = HEX[raw[13] >> 4];
        out[31] = HEX[raw[13] & 15];
        out[32] = HEX[raw[14] >> 4];
        out[33] = HEX[raw[14] & 15];
        out[34] = HEX[raw[15] >> 4];
        out[35] = HEX[raw[15] & 15];
        return out.join('');
    };
}());
