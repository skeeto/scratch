# This is free and unencumbered software released into the public domain.

import asyncio
import collections

class ChannelClosed(Exception):
    """Raised when Channel.get() is called on a closed, empty channel."""
    pass

class Channel:
    """A channel is a tool for passing values between tasks.

    The default channel is unbuffered, meaning that put() blocks until
    there's a receiver on the other size to get(), creating a rendezvous
    synchronization point between the two tasks.

    A buffered channel has an internal queue and will accept up to
    "size" values before blocking. This is less often useful than
    unbuffered channels.

    Channels are asynchronous generators and so can be used with in
    "async for" statements. To terminate iteration, a producer calls
    close() on the channel. It is an error to close a channel more than
    once. Using get() on a closed, empty channel raises ChannelClosed.

    Like asyncio.Queue, channels also support task_done() and join()
    with the same semantics.

    Channels are a replacement for asyncio.Queue since they have better
    semantics. The problems with asyncio.Queue are: 1) unbounded by
    default, 2) do not support unbuffered operation, and 3) do not
    support asynchronous iteration.

    Example as a producer/consumer asynchronous generator:

        async def producer(channel):
            for input in inputs:
                await channel.put(input)
            channel.close()

        async def consumer(channel):
            async for message in channel:
                ...
    """

    def __init__(self, size=0):
        """Initialize a new channel, unbuffered by default."""
        self._put = asyncio.Semaphore(size)
        self._get = asyncio.Semaphore(0)
        self._queue = collections.deque()
        self._closed = False
        self._tasks = 0
        self._done = asyncio.Event()

    async def put(self, value):
        """Put a value in the channel, blocking until there is room.

        It is an error to put() on a closed channel."""
        assert not self._closed
        await self._put.acquire()
        self._tasks += 1
        self._done.clear()
        self._queue.appendleft(value)
        self._get.release()

    async def get(self):
        """Get a value from the channel, blocking until there is one.

        Raises ChannelClosed if the channel is closed and empty."""
        self._put.release()
        await self._get.acquire()
        if self._closed:
            self._get.release() # turnstile
            if len(self._queue) == 0:
                raise ChannelClosed('channel is closed and empty')
        return self._queue.pop()

    async def join(self):
        """Block until all items in the channel have been processed."""
        await self._done.wait()

    def task_done(self):
        """Indicate that a channel value has been processed."""
        assert self._tasks > 0
        self._tasks -= 1
        if self._tasks == 0:
            self._done.set()

    def close(self):
        """Close the channel, stopping iteration after values are consumed.

        It is an error to put() on a closed channel.
        """
        assert not self._closed
        self._closed = True
        self._get.release()

    def closed(self):
        """Return True if the channel has been closed."""
        return self._closed

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self.get()
        except ChannelClosed:
            raise StopAsyncIteration

import math
import random
import unittest

async def _test_iter(self, size, n):
    channel = Channel(size)
    inputs = set(range(n))
    outputs = set()

    async def producer():
        for i in inputs:
            await channel.put(i)
        channel.close()

    async def consumer():
        async for message in channel:
            outputs.add(message)
            await asyncio.sleep(random.uniform(0.0, 1e-6))

    nconsumers = math.floor(math.sqrt(n))
    consumers = [asyncio.create_task(consumer()) for _ in range(nconsumers)]
    await producer()
    for consumer in consumers:
        await consumer
    self.assertEqual(inputs, outputs)

async def _test_join(self, size, n):
    channel = Channel(size)
    inputs = set(range(n))
    outputs = set()

    async def producer():
        for i in inputs:
            await channel.put(i)
        await channel.join()

    async def consumer():
        while True:
            message = await channel.get()
            outputs.add(message)
            await asyncio.sleep(random.uniform(0.0, 1e-6))
            channel.task_done()

    nconsumers = math.floor(math.sqrt(n))
    consumers = [asyncio.create_task(consumer()) for _ in range(nconsumers)]
    await producer()
    for consumer in consumers:
        consumer.cancel()
    self.assertEqual(inputs, outputs)

async def _test_closed(self):
    init = asyncio.Semaphore(0)
    channel = Channel()

    async def waiter():
        with self.assertRaises(ChannelClosed):
            init.release()
            await channel.get()

    # Use multiple waiters in order to test the turnstile
    waiters = [asyncio.create_task(waiter()) for _ in range(4)]

    # Wait for all waiters to block on the channel before closing it
    for _ in waiters:
        await init.acquire()

    channel.close()
    await asyncio.gather(*waiters)

class _ChannelTestCase(unittest.TestCase):
    def test_unbuffered_iter(self):
        for _ in range(32):
            asyncio.run(_test_iter(self, 0, 1024))

    def test_buffered_iter(self):
        for _ in range(32):
            asyncio.run(_test_iter(self, 32, 1024))

    def test_unbuffered_join(self):
        for _ in range(32):
            asyncio.run(_test_join(self, 0, 1024))

    def test_buffered_join(self):
        for _ in range(32):
            asyncio.run(_test_join(self, 32, 1024))

    def test_closed(self):
        asyncio.run(_test_closed(self))

if __name__ == '__main__':
    unittest.main()
