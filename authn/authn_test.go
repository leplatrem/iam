package authn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthenticator(t *testing.T) {
	_, err := NewAuthenticator("http://auth0.com")
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "https:// scheme")

	authn1, err := NewAuthenticator("https://auth0.com")
	require.Nil(t, err)
	authn2, err := NewAuthenticator("https://auth0.com")
	require.Nil(t, err)
	assert.Equal(t, authn1, authn2)

	other, err := NewAuthenticator("https://auth1.com")
	require.Nil(t, err)
	assert.NotEqual(t, authn1, other)
}
