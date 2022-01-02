package sshbuf

func (b *Buffer) ReadString() (string, error) {
	len, err := b.ReadUint32()
	if err != nil {
		return "", err
	}

	data, err := b.ReadN(int(len))
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (b *Buffer) WriteString(s string) error {
	err := b.WriteUint32(uint32(len(s)))
	if err != nil {
		return err
	}

	_, err = b.Write([]byte(s))
	return err
}

func (b *Buffer) ReadBinary() ([]byte, error) {
	len, err := b.ReadUint32()
	if err != nil {
		return nil, err
	}

	data, err := b.ReadN(int(len))
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (b *Buffer) WriteBinary(s []byte) error {
	err := b.WriteUint32(uint32(len(s)))
	if err != nil {
		return err
	}

	_, err = b.Write(s)
	return err
}
