# This is free and unencumbered software released into the public domain.

import asyncio

class Barrier:
    """A barrier creates a rendezvous point for a group of tasks.

    Barriers are reusable, used to keep a group of related tasks in
    \"phase\" with each other. No task can pass a barrier until all
    other tasks have also reached the barrier. When all tasks reach the
    barrier, the barrier is reset and all tasks are released.
    """

    def __init__(self, n):
        """Create a barrier for a group of N tasks."""
        assert n > 0
        self._n = n - 1
        self._count = 0
        self._event = asyncio.Event()

    async def wait(self):
        """Wait until all other tasks have also waited."""
        if self._count == self._n:
            self._count = 0
            self._event.set()
            self._event.clear()
            await asyncio.sleep(0) # yield
        else:
            self._count += 1
            await self._event.wait()

import random
import unittest

def _reorder(n):
    order = [i for i in range(n)]
    while True:
        random.shuffle(order)
        for i in order:
            yield i

async def _test_barrier(self, n):
    barrier = Barrier(n)
    target = (1 << n) - 1
    state = 0
    sleeps = _reorder(n)

    async def worker(i):
        nonlocal state
        for _ in range(256):
            # Shuffle the task schedule order
            for _ in range(next(sleeps)):
                await asyncio.sleep(0)

            state |= 1 << i
            await barrier.wait()

            # Check that all tasks are in the same phase
            self.assertEqual(state, target)
            await barrier.wait()

            state ^= 1 << i
            await barrier.wait()

            # Check that all tasks are in the same phase
            self.assertEqual(state, 0)
            await barrier.wait()

    await asyncio.gather(*[asyncio.create_task(worker(i)) for i in range(n)])

class _BarrierTestCase(unittest.TestCase):
    def test_barrier(self):
        for n in range(16):
            asyncio.run(_test_barrier(self, n + 1))

if __name__ == '__main__':
    unittest.main()
