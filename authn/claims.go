package authn

import (
	"encoding/json"
	"github.com/pkg/errors"
)

// claimExtractor is in charge of extracting meaningful info from JWT payload.
type claimExtractor interface {
	Extract(payload []byte) (*UserInfo, error)
}

// claims is the set of information we extract from the JWT payload or the user
// profile information.
type claims struct {
	Subject string   `json:"sub,omitempty"`
	Email   string   `json:"email,omitempty"`
	Groups  []string `json:"groups,omitempty"`
}

type defaultClaimExtractor struct{}

func (*defaultClaimExtractor) Extract(payload []byte) (*UserInfo, error) {
	var claims = &claims{}
	err := json.Unmarshal(payload, claims)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse user info from payload")
	}
	return &UserInfo{
		ID:     claims.Subject,
		Email:  claims.Email,
		Groups: claims.Groups,
	}, nil
}

var defaultExtractor = &defaultClaimExtractor{}
