package authn

import (
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// Claims is the set of information we extract from the JWT payload.
type Claims struct {
	Subject  string       `json:"sub,omitempty"`
	Audience jwt.Audience `json:"aud,omitempty"`
	Email    string       `json:"email,omitempty"`
	Groups   []string     `json:"groups,omitempty"`
}

// claimExtractor is in charge of extracting meaningful info from JWT payload.
type claimExtractor interface {
	Extract(*jwt.JSONWebToken, *jose.JSONWebKey) (*Claims, error)
}

type defaultClaimExtractor struct{}

func (*defaultClaimExtractor) Extract(token *jwt.JSONWebToken, key *jose.JSONWebKey) (*Claims, error) {
	claims := &Claims{}
	err := token.Claims(key, claims)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

var defaultExtractor = &defaultClaimExtractor{}
