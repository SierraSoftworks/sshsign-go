package sshbuf

import "bytes"

type Buffer struct {
	buf bytes.Buffer
}

func New() *Buffer {
	return &Buffer{buf: *bytes.NewBuffer(nil)}
}

func FromBytes(b []byte) *Buffer {
	return &Buffer{buf: *bytes.NewBuffer(b)}
}

func (b *Buffer) Bytes() []byte {
	return b.buf.Bytes()
}

func (b *Buffer) Len() int {
	return b.buf.Len()
}

func (b *Buffer) Cap() int {
	return b.buf.Cap()
}

func (b *Buffer) Reset() {
	b.buf.Reset()
}
