package bufferpool

import (
	"testing"
	"unsafe"
)

func TestPoolReuse(t *testing.T) {
	p := New(128)
	b1 := p.Get()
	ptr1 := uintptr(unsafe.Pointer(&b1[0]))
	p.Put(b1)
	b2 := p.Get()
	ptr2 := uintptr(unsafe.Pointer(&b2[0]))
	if ptr1 != ptr2 {
		t.Fatalf("expected pool to reuse buffer")
	}
}
