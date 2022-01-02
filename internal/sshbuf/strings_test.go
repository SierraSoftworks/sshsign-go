package sshbuf_test

import (
	"testing"

	"github.com/SierraSoftworks/sshsign-go/internal/sshbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStrings(t *testing.T) {
	b := new(sshbuf.Buffer)

	require.NoError(t, b.WriteString("hello"))
	assert.Equal(t, 9, b.Len())
	assert.Equal(t, b.Bytes(), []byte("\x00\x00\x00\x05hello"))

	s, err := b.ReadString()
	require.NoError(t, err)
	assert.Equal(t, "hello", s)
}

func TestBinary(t *testing.T) {
	b := new(sshbuf.Buffer)

	require.NoError(t, b.WriteBinary([]byte("hello")))
	assert.Equal(t, 9, b.Len())
	assert.Equal(t, b.Bytes(), []byte("\x00\x00\x00\x05hello"))

	out, err := b.ReadBinary()
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), out)
}
