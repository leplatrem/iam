package authn

import (
	"encoding/json"

	"github.com/pkg/errors"
)

// mozillaClaims is a specific struct to extract emails and groups from
// the JWT or the profile info using Mozilla specific attributes.
type mozillaClaims struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email"`
	Emails  []string `json:"https://sso.mozilla.com/claim/emails"`
	Groups  []string `json:"https://sso.mozilla.com/claim/groups"`
}

type mozillaClaimExtractor struct{}

func (*mozillaClaimExtractor) Extract(payload []byte) (*UserInfo, error) {
	var userInfo = &mozillaClaims{}
	err := json.Unmarshal(payload, userInfo)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse Mozilla user info from payload")
	}

	// In case the JWT was not requested with the `profile` or `email` scope,
	// we may not obtain the email(s).
	email := userInfo.Email
	if email == "" && len(userInfo.Emails) > 0 {
		email = userInfo.Emails[0]
	}

	return &UserInfo{
		ID:     userInfo.Subject,
		Email:  email,
		Groups: userInfo.Groups,
	}, nil
}

var mozillaExtractor = &mozillaClaimExtractor{}
