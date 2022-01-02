package sshbuf_test

import (
	"testing"

	"github.com/SierraSoftworks/sshsign-go/internal/sshbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadWrite(t *testing.T) {
	b := new(sshbuf.Buffer)
	n, err := b.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, []byte("hello"), b.Bytes())

	require.NoError(t, b.WriteByte(' '))
	assert.Equal(t, []byte("hello "), b.Bytes())

	out := make([]byte, 3)
	n, err = b.Read(out)
	require.NoError(t, err)
	assert.Equal(t, n, 3)
	assert.Equal(t, []byte("hel"), out)

	c, err := b.ReadByte()
	require.NoError(t, err)
	assert.Equal(t, byte('l'), c)

	out, err = b.ReadN(2)
	require.NoError(t, err)
	assert.Equal(t, []byte("o "), out)
}
