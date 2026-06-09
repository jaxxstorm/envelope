package bufferpool

import "sync"

type Pool struct {
	size int
	pool sync.Pool
}

func New(size int) *Pool {
	p := &Pool{size: size}
	p.pool.New = func() any {
		b := make([]byte, size)
		return b
	}
	return p
}

func (p *Pool) Get() []byte {
	b := p.pool.Get().([]byte)
	return b[:p.size]
}

func (p *Pool) Put(b []byte) {
	if cap(b) < p.size {
		return
	}
	p.pool.Put(b[:p.size])
}

func (p *Pool) Size() int {
	return p.size
}
