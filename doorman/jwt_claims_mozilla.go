package doorman

import (
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// MozillaClaims uses specific attributes for emails and groups
type MozillaClaims struct {
	Subject  string       `json:"sub"`
	Audience jwt.Audience `json:"aud"`
	Email    string       `json:"email"`
	Emails   []string     `json:"https://sso.mozilla.com/claim/emails"`
	Groups   []string     `json:"https://sso.mozilla.com/claim/groups"`
}

type mozillaClaimExtractor struct{}

func (*mozillaClaimExtractor) Extract(token *jwt.JSONWebToken, key *jose.JSONWebKey) (*Claims, error) {
	mozclaims := MozillaClaims{}
	err := token.Claims(key, &mozclaims)
	if err != nil {
		return nil, err
	}

	// In case the JWT was not requested with the profile or email scope.
	email := mozclaims.Email
	if email == "" && len(mozclaims.Emails) > 0 {
		email = mozclaims.Emails[0]
	}

	claims := Claims{
		Subject:  mozclaims.Subject,
		Audience: mozclaims.Audience,
		Email:    email,
		Groups:   mozclaims.Groups,
	}

	return &claims, nil
}

var mozillaExtractor = &mozillaClaimExtractor{}
