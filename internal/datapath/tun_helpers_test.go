package datapath

import (
	"errors"
	"testing"

	"github.com/jaxxstorm/envelope/internal/bufferpool"
)

type fakeTun struct {
	readData []byte
	readErr  error
	writes   [][]byte
}

func (f *fakeTun) Read(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	n := copy(p, f.readData)
	return n, nil
}

func (f *fakeTun) Write(p []byte) (int, error) {
	f.writes = append(f.writes, append([]byte(nil), p...))
	return len(p), nil
}

func TestReadTunPacket(t *testing.T) {
	pool := bufferpool.New(16)
	ft := &fakeTun{readData: []byte{0x01, 0x02, 0x03}}
	buf, n, err := readTunPacket(ft, pool)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 3 {
		t.Fatalf("unexpected length: %d", n)
	}
	pool.Put(buf)
}

func TestReadTunPacketError(t *testing.T) {
	pool := bufferpool.New(16)
	ft := &fakeTun{readErr: errors.New("boom")}
	buf, _, err := readTunPacket(ft, pool)
	if err == nil {
		t.Fatalf("expected error")
	}
	if buf != nil {
		t.Fatalf("expected nil buffer on error")
	}
}

func TestWriteTunPacket(t *testing.T) {
	ft := &fakeTun{}
	payload := []byte{0xaa, 0xbb}
	if err := writeTunPacket(ft, payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ft.writes) != 1 {
		t.Fatalf("expected one write")
	}
}
