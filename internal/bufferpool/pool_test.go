package bufferpool

import (
	"sync"
	"testing"
)

func TestPoolSizeAndCapacityContract(t *testing.T) {
	p := New(128)
	if p.Size() != 128 {
		t.Fatalf("size=%d, want 128", p.Size())
	}
	buffer := p.Get()
	if len(buffer) != 128 || cap(buffer) < 128 {
		t.Fatalf("buffer len=%d cap=%d", len(buffer), cap(buffer))
	}
	p.Put(buffer[:64])
	buffer = p.Get()
	if len(buffer) != 128 || cap(buffer) < 128 {
		t.Fatalf("reissued buffer len=%d cap=%d", len(buffer), cap(buffer))
	}
	// Undersized buffers are ignored rather than poisoning future Gets.
	p.Put(make([]byte, 64))
	buffer = p.Get()
	if len(buffer) != 128 || cap(buffer) < 128 {
		t.Fatalf("buffer after undersized Put len=%d cap=%d", len(buffer), cap(buffer))
	}
}

func TestPoolConcurrentContract(t *testing.T) {
	p := New(256)
	var workers sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		workers.Add(1)
		go func(value byte) {
			defer workers.Done()
			for range 1000 {
				buffer := p.Get()
				if len(buffer) != 256 || cap(buffer) < 256 {
					t.Errorf("concurrent buffer len=%d cap=%d", len(buffer), cap(buffer))
					return
				}
				buffer[0] = value
				p.Put(buffer)
			}
		}(byte(worker))
	}
	workers.Wait()
}
