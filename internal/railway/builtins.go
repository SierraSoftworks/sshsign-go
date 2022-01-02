package railway

func (r *Railway) MustString(s string, err error) string {
	r.addError(err)

	return s
}

func (r *Railway) MustInt(i int, err error) int {
	r.addError(err)

	return i
}

func (r *Railway) MustInt64(i int64, err error) int64 {
	r.addError(err)

	return i
}

func (r *Railway) MustUint32(i uint32, err error) uint32 {
	r.addError(err)

	return i
}

func (r *Railway) MustUint64(i uint64, err error) uint64 {
	r.addError(err)

	return i
}

func (r *Railway) MustBytes(i []byte, err error) []byte {
	r.addError(err)

	return i
}
