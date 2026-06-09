package datapath

import "github.com/jaxxstorm/envelope/internal/bufferpool"

type tunReader interface {
	Read([]byte) (int, error)
}

type tunWriter interface {
	Write([]byte) (int, error)
}

func readTunPacket(reader tunReader, pool *bufferpool.Pool) ([]byte, int, error) {
	buf := pool.Get()
	n, err := reader.Read(buf)
	if err != nil {
		pool.Put(buf)
		return nil, 0, err
	}
	return buf, n, nil
}

func writeTunPacket(writer tunWriter, payload []byte) error {
	_, err := writer.Write(payload)
	return err
}
