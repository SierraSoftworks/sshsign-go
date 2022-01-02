package sshbuf

func (b *Buffer) ReadUint32() (uint32, error) {
	data, err := b.ReadN(4)
	if err != nil {
		return 0, err
	}

	return uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]), nil
}

func (b *Buffer) WriteUint32(n uint32) error {
	_, err := b.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	return err
}
