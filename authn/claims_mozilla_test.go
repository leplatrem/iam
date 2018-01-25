package authn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMozillaClaimsExtractor(t *testing.T) {
	data := []byte(`<"sub"`)
	_, err := mozillaExtractor.Extract(data)
	require.NotNil(t, err)

	data = []byte(`{"sub":"mleplatre|Mozilla-LDAP|","email":"m@mozilla.com","https://sso.mozilla.com/claim/groups":["g1", "cloudservices_dev", "irccloud"]}`)
	userinfo, err := mozillaExtractor.Extract(data)
	require.Nil(t, err)
	assert.Contains(t, userinfo.ID, "|Mozilla-LDAP|")
	assert.Contains(t, userinfo.Email, "@mozilla.com")
	assert.Contains(t, userinfo.Groups, "cloudservices_dev", "irccloud")

	// Email provided in `email` field instead of https://sso.../emails list
	data = []byte(`{"sub":"mleplatre|Mozilla-LDAP","https://sso.mozilla.com/claim/emails":["m@mozilla.com"],"https://sso.mozilla.com/claim/groups":["g1", "cloudservices_dev", "irccloud"]}`)
	userinfo, err = mozillaExtractor.Extract(data)
	require.Nil(t, err)
	assert.Contains(t, userinfo.Email, "@mozilla.com")
}
