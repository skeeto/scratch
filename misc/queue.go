// Demonstrates a single-consumer, single-producer queue shared between
// a C consumer and Go producer.
// Ref: https://nullprogram.com/blog/2022/05/14/
// This is free and unencumbered software released into the public domain.
package main

// #include <stdint.h>
//
// static int queue_pop(uint32_t *q, int exp)
// {
//     uint32_t r = __atomic_load_n(q, __ATOMIC_ACQUIRE);
//     uint32_t M = (1 << exp) - 1;
//     uint32_t h = r     & M;
//     uint32_t t = r>>16 & M;
//     return h == t ? -1 : t;
// }
//
// static int queue_commit(uint32_t *q)
// {
//     __atomic_fetch_add(q, 0x10000, __ATOMIC_RELEASE);
// }
//
// static uint64_t consumer(uint32_t *q, int exp, const uint64_t *slots)
// {
//     uint64_t v, sum = 0;
//     do {
//         int i;
//         do {
//             i = queue_pop(q, exp);
//         } while (i < 0);  // note: busy-wait while empty
//         v = slots[i];
//         queue_commit(q);
//		   sum += v;
//     } while (v);
//     return sum;
// }
import "C"
import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
)

type Queue struct {
	Q uint32
	M uint32
}

func NewQueue(exp int) Queue {
	return Queue{0, uint32((1 << exp) - 1)}
}

func (q *Queue) Push() int {
	r := atomic.LoadUint32(&q.Q)
	h := r & q.M
	t := r >> 16 & q.M
	n := (h + 1) & q.M
	if r&0x8000 != 0 {
		// No AndUint32, so subtract the bit instead
		atomic.AddUint32(&q.Q, -0x8000&0xffffffff)
	}
	if n == t {
		return -1
	}
	return int(h)
}

func (q *Queue) Commit() {
	atomic.AddUint32(&q.Q, 1)
}

func main() {
	const (
		exp  = 5
		nums = 10_000_000
	)
	var (
		sum   uint64
		slots [1 << exp]uint64
		q     = NewQueue(exp)
		wg    sync.WaitGroup
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; n <= nums; n++ {
			var i int
			for { // note: busy-wait while full
				i = q.Push()
				if i >= 0 {
					break
				}
			}
			var v uint64
			if n < nums {
				v = rand.Uint64()
			}
			slots[i] = v
			q.Commit()
			sum += v
		}
	}()

	r := C.consumer((*C.uint32_t)(&q.Q), exp, (*C.uint64_t)(&slots[0]))
	// Technically this WaitGroup is not needed since the queue
	// synchronizes the goroutines when the queue empties. The
	// consumer's exit has a happens-after ordering with the producer's
	// final commit. However this synchronization is not visible to the
	// data race detector, causing a false positive. The extra WaitGroup
	// synchronization keeps it happy.
	wg.Wait()

	fmt.Printf("want %016x, got %016x\n", sum, r)
}
