# Infinite maze walker

An animation of a robot traversing down an infinitely tall maze generated
a row at a time using [Eller's Algorithm][ea]. I wrote it as a fun little
extra in a presentation on debuggers. My slides were HTML, so I could add
arbitrary scripts and animation. The code is not quite as clean and tidy
as usual because I stopped as soon as I had it working.

In reality the top row is destroyed when a new row is added, and so the
robot can only travel the visible portion of the maze. It targets the
furthest lowest reachable cell, travels to it, and then repeats. It's
possible for the robot to get stuck in a branch inaccessible to the rest
of the maze because the connecting path fell off the top. In this case it
uses a special "dig" action to destroy a wall and continue. However, I've
chosen parameters that make this exceedingly rare, so don't sit waiting to
see it dig. You'll need to adjust the parameters to make it more likely.

## Build

Almost any build of Clang will work. Run `make`, then visit `index.html`
in your favorite WebAssembly-capable browser.


[ea]: https://weblog.jamisbuck.org/2010/12/29/maze-generation-eller-s-algorithm
