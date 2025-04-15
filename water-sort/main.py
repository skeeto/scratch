# WebAssembly via wasm3 with Python tkinter GUI
#   $ pip install pywasm3
#   $ make water-sort.wasm
#   $ python main.py
#
# This is mostly a proof of concept. While wasm3 is just *barely* fast
# enough to run the solver in real-time, tkinter is horrifically slow,
# making the interface feel sluggish and unpleasant. All the time is
# spent inside Tk.update(). So active rendering is unimplemented, which
# would be done using Tk.after(). Pygame would be more appropriate, but
# I dislike it for different reasons, and at least tkinter is built-in.

import enum
import re
import struct
import sys
import time
import tkinter as tk
import wasm3

class Input(enum.IntEnum):
    NONE  = 0
    CLICK = 1
    HINT  = 2
    RESET = 3
    UNDO  = 4

class Draw(enum.IntEnum):
    BOX  = 0
    FILL = 1

def getseeds():
    with open("seeds.txt") as f:
        return [int(x) for x in re.split("[\\s,]+", f.read()) if x]

def loadgame():
    env     = wasm3.Environment()
    runtime = env.new_runtime(2**12)
    with open("water-sort.wasm", "rb") as f:
        runtime.load(env.parse_module(f.read()))
    return (
        runtime.get_memory(0),
        runtime.find_function("game_init"),
        runtime.find_function("game_update"),
        runtime.find_function("game_render"),
    )

def now():
    return int(time.monotonic() * 1000)

def main():
    memory, init, update, render = loadgame()

    seeds  = getseeds()
    dims   = 640, 640
    mouse  = [0, 0]
    puzzle = 0
    start  = now()

    window = tk.Tk()
    window.resizable(False, False)

    canvas = tk.Canvas(window, width=dims[0], height=dims[1], bg="black")
    canvas.pack()

    def redraw():
        update(Input.NONE, *mouse, now()-start)
        dl = render(*dims, *mouse)
        active, nops = struct.unpack_from("<ii", memory, dl)
        ops = memory[dl+8:]
        for i in range(nops):
            mode, rgb, x, y, w, h = struct.unpack_from("<iiiiii", ops, 24*i)
            color = f"#{rgb:06x}"
            if mode == Draw.BOX:
                canvas.create_rectangle(x, y, x+w, y+h, outline=color)
            elif mode == Draw.FILL:
                canvas.create_rectangle(x, y, x+w, y+h, fill=color, width=0)
        window.update()  # VERY SLOW

    def setpuzzle():
        init(seeds[puzzle])
        window.title(f"Water Sort #{puzzle+1}")
        redraw()
    setpuzzle()

    def leftclick(event):
        update(Input.CLICK, event.x, event.y, now()-start)
        redraw()
    canvas.bind("<Button-1>", leftclick)

    def middleclick(event):
        update(Input.HINT, event.x, event.y, now()-start)
        redraw()
    canvas.bind("<Button-2>", middleclick)
    window.bind("<KeyPress-h>", middleclick)

    def rightclick(event):
        update(Input.UNDO, event.x, event.y, now()-start)
        redraw()
    canvas.bind("<Button-3>", rightclick)
    window.bind("<KeyPress-u>", rightclick)

    def motion(event):
        mouse[0], mouse[1] = event.x, event.y
        redraw()
    canvas.bind("<Motion>", motion)

    def leftarrow(_):
        nonlocal puzzle
        puzzle = (puzzle + len(seeds) - 1) % len(seeds)
        setpuzzle()
    window.bind("<Left>", leftarrow)

    def rightarrow(_):
        nonlocal puzzle
        puzzle = (puzzle + 1) % len(seeds)
        setpuzzle()
    window.bind("<Right>", rightarrow)

    def quit(_):
        sys.exit(0)
    window.bind("<KeyPress-q>", quit)

    def reset(_):
        setpuzzle()
    window.bind("<KeyPress-r>", reset)

    redraw()
    window.mainloop()

main()
