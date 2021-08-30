-- UUID generator for Lua 5.3

-- Entropy pool for gathering random bytes
local pool = {i = 0, j = 0, k = 0}
for i = 1, 256 do
    pool[i] = i - 1
end

-- Absorb a byte into the entropy pool
local function absorb(byte)
    pool.j = (pool.j + pool[pool.i + 1] + byte) % 256
    pool[pool.i + 1], pool[pool.j + 1] = pool[pool.j + 1], pool[pool.i + 1]
    pool.j = (pool.j + 1) % 256
    pool.k = (pool.k + 1) % 256
end

-- Absorb an arbitrary value into the entropy pool
local function absorbs(value)
    local string = tostring(value)
    for i = 1, #string do
        absorb(string:byte(i))
    end
end

-- Stir the entropy pool
local function stir()
    if pool.k > 0 then
        pool.j = (pool.j + 1) % 256
        repeat
            absorb(pool.k)
        until pool.k == 0
    end
end

-- Emit a single byte from the entropy pool
local function squeeze()
    pool.j = (pool.j + pool.i) % 256
    pool.i = (pool.i + 1) % 256
    pool[pool.i + 1], pool[pool.j + 1] = pool[pool.j + 1], pool[pool.i + 1]
    return pool[1 + (pool[pool.i + 1] + pool[pool.j + 1]) % 256]
end

-- Mix random data into the entropy pool
absorbs({})
absorbs(absorbs)
absorbs(os.time())
for i = 1, 1 << 12 do
    local clock = os.clock
    local count = 0
    local start = clock()
    while start == clock() do
        count = count + 1
    end
    absorbs(start)
    absorbs(count)
end
stir()

-- Initialze the lookup tables for UUID generation
local hex_hi = {}
local hex_lo = {}
for i = 0, 255 do
    hex_lo[i] = ('0123456789abcdef'):byte(1 + (i % 16))
    hex_hi[i] = ('0123456789abcdef'):byte(1 + (i >> 4))
end

-- Generate a new UUID and return it as a string
local function uuid()
    local bytes = {}
    for i = 1, 16 do
        bytes[i] = squeeze()
    end
    return string.char(
        hex_lo[bytes[ 1]],
        hex_hi[bytes[ 1]],
        hex_lo[bytes[ 2]],
        hex_hi[bytes[ 2]],
        hex_lo[bytes[ 3]],
        hex_hi[bytes[ 3]],
        hex_lo[bytes[ 4]],
        hex_hi[bytes[ 4]],
        0x2d,
        hex_lo[bytes[ 5]],
        hex_hi[bytes[ 5]],
        hex_lo[bytes[ 6]],
        hex_hi[bytes[ 6]],
        0x2d,
        0x34,
        hex_hi[bytes[ 7]],
        hex_lo[bytes[ 8]],
        hex_hi[bytes[ 8]],
        0x2d,
        ('89ab'):byte(1 + (bytes[ 9] & 0x3)),
        hex_hi[bytes[ 9]],
        hex_lo[bytes[10]],
        hex_hi[bytes[10]],
        0x2d,
        hex_lo[bytes[11]],
        hex_hi[bytes[11]],
        hex_lo[bytes[12]],
        hex_hi[bytes[12]],
        hex_lo[bytes[13]],
        hex_hi[bytes[13]],
        hex_lo[bytes[14]],
        hex_hi[bytes[14]],
        hex_lo[bytes[15]],
        hex_hi[bytes[15]],
        hex_lo[bytes[16]],
        hex_hi[bytes[16]]
    )
end

return uuid
