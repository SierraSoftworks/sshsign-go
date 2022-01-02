package sshbuf

import "io"

func (b *Buffer) Write(p []byte) (int, error) {
	return b.buf.Write(p)
}

func (b *Buffer) WriteByte(c byte) error {
	return b.buf.WriteByte(c)
}

func (b *Buffer) Read(p []byte) (int, error) {
	return b.buf.Read(p)
}

func (b *Buffer) ReadByte() (byte, error) {
	return b.buf.ReadByte()
}

func (b *Buffer) ReadN(n int) ([]byte, error) {
	out := make([]byte, n)
	i, err := b.Read(out)
	if err != nil {
		return nil, err
	}

	if i != n {
		return nil, io.ErrUnexpectedEOF
	}

	return out, nil
}
