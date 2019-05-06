-- Sponge4: a simple sponge based on RC4
-- https://redd.it/a9k8yj
--
-- sponge4 = require('sponge4')
-- local input = 'hello world'
-- local s = sponge4.new()
-- for i = 1, #input do
--     s:absorb(input:byte(i))
-- end
-- s:squeeze()  -- 103
-- s:squeeze()  -- 239
-- s:squeeze()  -- 169

local sponge4 = {}
sponge4.__index = sponge4

local init = {}
for i = 1, 256 do
    init[i] = i - 1
end

-- Create a new sponge in the default state.
function sponge4.new()
    return setmetatable({i = 0, j = 0, k = 0, table.unpack(init)}, sponge4)
end

-- Absorb a single byte (0-255) into the sponge.
function sponge4:absorb(byte)
    self.j = (self.j + self[self.i + 1] + byte) % 256
    self[self.i + 1], self[self.j + 1] = self[self.j + 1], self[self.i + 1]
    self.j = (self.j + 1) % 256
    self.k = (self.k + 1) % 256
end

-- Absorb the special "stop" symbol into the sponge.
function sponge4:stop()
    self.j = (self.j + 1) % 256
end

-- Squeeze a single byte (0-255) of output from the sponge.
function sponge4:squeeze()
    if self.k > 0 then
        self:stop(self)
        repeat
            self:absorb(self.k)
        until self.k == 0
    end

    self.j = (self.j + self.i) % 256
    self.i = (self.i + 1) % 256
    self[self.i + 1], self[self.j + 1] = self[self.j + 1], self[self.i + 1]
    return self[1 + (self[self.i + 1] + self[self.j + 1]) % 256]
end

return sponge4
