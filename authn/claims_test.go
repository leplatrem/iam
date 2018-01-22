package authn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultClaimsExtractor(t *testing.T) {
	data := []byte(`<"sub"`)
	_, err := defaultExtractor.Extract(data)
	require.NotNil(t, err)

	data = []byte(`{"sub":"google-oauth2|104102306111350576628"}`)
	userinfo, err := defaultExtractor.Extract(data)
	require.Nil(t, err)
	assert.Equal(t, "google-oauth2|104102306111350576628", userinfo.ID)
}
