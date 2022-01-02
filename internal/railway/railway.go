package railway

type Railway struct {
	err error
}

func New() *Railway {
	return &Railway{}
}

func (r *Railway) addError(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *Railway) Err() error {
	return r.err
}

func (r *Railway) Must(err error) {
	r.addError(err)
}
