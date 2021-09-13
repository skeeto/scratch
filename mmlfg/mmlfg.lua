-- Middle Multiplicative Lagged Fibonacci Generator
-- This is free and unencumbered software released into the public domain.

-- Returns a function generating a 64-bit result on each call.
function mmlfg(seed)
    local i = 15
    local j = 13
    local s = {}
    for i = 1, 15 do
        seed = seed*0x3243f6a8885a308d + 1111111111111111111
        s[i] = seed ~ seed>>31 | 1
    end

    return function()
        -- Update internal state
        local a, b = s[i], s[j]
        s[i] = a * b
        i = i > 1 and i-1 or 15
        j = j > 1 and j-1 or 15

        -- 128-bit multiply for result
        local r00 = (a & 0xffffffff) * (b & 0xffffffff)
        local r10 = (a >> 32       ) * (b & 0xffffffff)
        local r01 = (a & 0xffffffff) * (b >> 32       )
        local r11 = (a >> 32       ) * (b >> 32       )
        local mid = (r00 >> 32) + (r10 & 0xffffffff) + r01
        local hi  = (r10 >> 32) + (mid >> 32       ) + r11
        local lo  = (mid << 32) | (r00 & 0xffffffff)

        -- Return middle of 128-bit product
        return hi<<32 | lo>>32
    end
end

-- Example
local r = {}
local v = {}
for i = 1, 4 do
    r[i] = mmlfg(i - 1)
end
for i = 1, 40 do
    for i = 1, #r do
        v[i] = string.format("%016x", r[i]())
    end
    print(table.concat(v, " "))
end
