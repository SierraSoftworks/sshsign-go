package railway_test

import (
	"fmt"
	"testing"

	"github.com/SierraSoftworks/sshsign-go/internal/railway"
	"github.com/stretchr/testify/assert"
)

func TestRailway(t *testing.T) {
	r := railway.New()
	assert.NoError(t, r.Err(), "the railway should start with no error")

	r.Must(nil)
	assert.NoError(t, r.Err(), "the railway should not error after a nil step")

	r.Must(fmt.Errorf("error"))
	assert.Error(t, r.Err(), "the railway should report an error after an error is seen")

	r.Must(nil)
	assert.Error(t, r.Err(), "the railway should continue reporting an error even after future steps")
}
