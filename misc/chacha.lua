-- chacha.lua -- ChaCha stream cipher for Lua 5.3
-- Supports both 32-bit and 64-bit integers
--
-- state = chacha.new(key, iv [, rounds])
-- block = chacha.generate(state)
--
-- This is free and unencumbered software released into the public domain.
local chacha = {}

function chacha.new(key, iv, rounds)
    local s = {workspace = {}, rounds = rounds or 20}
    s[1] = 0x61707865 -- "expand 32-byte k"
    s[2] = 0x3320646e --
    s[3] = 0x79622d32 --
    s[4] = 0x6b206574 --
    s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12] =
        string.unpack('<I4I4I4I4I4I4I4I4', key)
    s[13] = 0
    s[14] = 0
    s[15], s[16] = string.unpack('<I4I4', iv)
    return s
end

local function rotate(v, n)
    return ((v << n) | (v >> (32 - n))) & 0xffffffff
end

local function quarterround(x, a, b, c, d)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ~ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ~ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ~ x[a],  8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ~ x[c],  7)
end

function chacha.generate(s)
    local x = s.workspace
    for i = 1, 16 do
        x[i] = s[i]
    end
    for _ = 1, s.rounds, 2 do
        quarterround(x,  1,  5,  9, 13)
        quarterround(x,  2,  6, 10, 14)
        quarterround(x,  3,  7, 11, 15)
        quarterround(x,  4,  8, 12, 16)
        quarterround(x,  1,  6, 11, 16)
        quarterround(x,  2,  7, 12, 13)
        quarterround(x,  3,  8,  9, 14)
        quarterround(x,  4,  5, 10, 15)
    end
    for i = 1, 16 do
        x[i] = (x[i] + s[i]) & 0xffffffff
    end
    s[13] = (s[13] + 1) & 0xffffffff
    if s[13] == 0 then
        s[14] = s[14] + 1
    end
    return string.pack('<I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4', table.unpack(x))
end

return chacha
