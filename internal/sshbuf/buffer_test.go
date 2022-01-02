package sshbuf_test

import (
	"testing"

	"github.com/SierraSoftworks/sshsign-go/internal/sshbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuffer(t *testing.T) {
	buf := new(sshbuf.Buffer)
	n, err := buf.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, buf.Len(), 5)
	assert.GreaterOrEqual(t, buf.Cap(), 5)
	assert.Equal(t, buf.Bytes(), []byte("hello"))

	buf.Reset()
	assert.Equal(t, buf.Len(), 0)
	assert.Equal(t, buf.Bytes(), []byte{})

	buf = sshbuf.FromBytes([]byte("hello"))
	assert.Equal(t, buf.Len(), 5)
	assert.GreaterOrEqual(t, buf.Cap(), 5)
	assert.Equal(t, buf.Bytes(), []byte("hello"))
}
