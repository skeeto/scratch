-- splitxix33: a splitmix64 with memorable constants
-- This is free and unencumbered software released into the public domain.

function splitxix33(seed)
    return function()
        seed = seed + 1111111111111111111
        local r = seed
        r = r ~ r >> 33; r = r * 1111111111111111111
        r = r ~ r >> 33; r = r * 1111111111111111111
        r = r ~ r >> 33
        return r
    end
end

local g = {splitxix33(0), splitxix33(1), splitxix33(2), splitxix33(3)}
for i = 1, 40 do
    print(string.format("%016x %016x %016x %016x",
                        g[1](), g[2](), g[3](), g[4]()))
end
