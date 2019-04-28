-- Kruskal maze generator
-- $ lua kruskal.lua > maze.ppm

local function cell()
    local s = {north = true, west = true}
    s.parent = s
    return s
end

local function find(s)
   if s.parent ~= s then
       s.parent = find(s.parent)
   end
   return s.parent
end

local function union(a, b)
    find(a).parent = b
end

local function drawrand(table)
    local i = math.random(#table)
    local e = table[i]
    table[i] = table[#table]
    table[#table] = nil
    return e
end

local function kruskal(width, height)
    local m = {width = width, height = height}
    local edges = {}
    for y = 0, height - 1 do
        for x = 0, width - 1 do
            local i = y * width + x + 1
            m[i] = cell()
            if y > 0 then
                table.insert(edges, {a = i, b = i - width, w = 'north'})
            end
            if x > 0 then
                table.insert(edges, {a = i, b = i - 1, w = 'west'})
            end
        end
    end
    -- destroy randomly-selected edges
    while #edges > 0 do
        local e = drawrand(edges)
        local a = m[e.a]
        local b = m[e.b]
        if find(a) ~= find(b) then
            union(a, b)
            a[e.w] = false
        end
    end
    return m
end

local function isconnected(maze, i, j)
    local a = maze[math.min(i, j)]
    local b = maze[math.max(i, j)]
    if math.abs(i - j) == 1 then
        return not b.west
    else
        return not b.north
    end
end

local function gradient(maze)
    local dx = {-1,  1,  0,  0}
    local dy = { 0,  0, -1,  1}
    local w = maze.width
    local h = maze.height
    local tx = w - 1
    local ty = h - 1

    -- queue
    local head = {x = 0, y = 0}
    local tail = head
    maze[1].visited = true

    while head do
        local x = head.x
        local y = head.y
        local i = y * w + x + 1
        if x == tx and y == ty then
            local n = i
            repeat
                maze[n].solution = true
                n = maze[n].gradient
            until not n
        end
        local s = maze[i]
        for j = 1, 4 do
            local cx = x + dx[j]
            local cy = y + dy[j]
            if cx >= 0 and cx < w and cy >= 0 and cy < h then
                local ci = cy * w + cx + 1
                local c = maze[ci]
                if not c.visited and isconnected(maze, i, ci) then
                    c.visited = true
                    c.gradient = i
                    tail.next = {x = cx, y = cy}
                    tail = tail.next
                end
            end
        end
        head = head.next
    end
    return maze
end

local function render(m, scale)
    local w = m.width
    local h = m.height
    local f = string.char(0, 0, 0)
    local b = string.char(255, 255, 255)
    local g = string.char(0, 255, 0)
    io.write(string.format('P6\n%d %d\n255\n', w * scale + 1, h * scale + 1))
    for py = 0, h * scale do
        local y = py // scale
        local sy = py % scale
        for px = 0, w * scale do
            if py == h * scale or px == w * scale then
                io.write(f)
            else
                local x = px // scale
                local sx = px % scale
                local c = m[y * w + x + 1]
                if sx == 0 and sy == 0 then
                    io.write(f)
                elseif sx == 0 and c.west then
                    io.write(f)
                elseif sy == 0 and c.north then
                    io.write(f)
                elseif c.solution then
                    io.write(g)
                else
                    io.write(b)
                end
            end
        end
    end
end

local WIDTH = 96
local HEIGHT = 64
local SIZE = 16

math.randomseed(os.time())
local maze = gradient(kruskal(WIDTH, HEIGHT))
render(maze, SIZE)
