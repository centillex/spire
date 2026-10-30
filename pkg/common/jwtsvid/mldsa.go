package jwtsvid

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/spire/pkg/common/pqjose"
)

// MLDSAClaims is the standard claim subset needed to validate an ML-DSA-65
// JWT-SVID.
type MLDSAClaims struct {
	Subject   string       `json:"sub"`
	Audience  Audience     `json:"aud"`
	Expiry    *NumericDate `json:"exp"`
	NotBefore *NumericDate `json:"nbf"`
	IssuedAt  *NumericDate `json:"iat"`
}

// Audience accepts the RFC 7519 string or array form.
type Audience []string

func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("aud claim must be a string or array of strings")
	}
	*a = many
	return nil
}

// NumericDate is a JWT NumericDate.
type NumericDate float64

func (n *NumericDate) UnmarshalJSON(data []byte) error {
	var value float64
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("claim must be a numeric date")
	}
	*n = NumericDate(value)
	return nil
}

func (n NumericDate) Time() time.Time {
	seconds := int64(n)
	nanos := int64((float64(n) - float64(seconds)) * 1e9)
	return time.Unix(seconds, nanos)
}

// ParseMLDSA parses an ML-DSA-65 JWT-SVID without verifying its signature and
// returns the parsed token, standard claims, and generic claim map. A token
// with another algorithm returns an error; callers may then try the classical
// path when their configuration explicitly permits it.
func ParseMLDSA(token string) (*pqjose.Token, *MLDSAClaims, map[string]any, error) {
	tok, err := pqjose.ParseJWT(token)
	if err != nil {
		return nil, nil, nil, err
	}

	var claims MLDSAClaims
	if err := json.Unmarshal(tok.Claims(), &claims); err != nil {
		return nil, nil, nil, fmt.Errorf("unable to parse JWT claims: %w", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(tok.Claims(), &generic); err != nil {
		return nil, nil, nil, fmt.Errorf("unable to parse JWT claims: %w", err)
	}
	return tok, &claims, generic, nil
}

// MLDSAWITClaims is the standard claim subset for an ML-DSA-65 WIT-SVID.
type MLDSAWITClaims struct {
	Subject   string         `json:"sub"`
	Audience  Audience       `json:"aud"`
	Expiry    *NumericDate   `json:"exp"`
	NotBefore *NumericDate   `json:"nbf"`
	IssuedAt  *NumericDate   `json:"iat"`
	CNF       map[string]any `json:"cnf"`
}

// ParseMLDSAWIT parses an ML-DSA-65 WIT-SVID without verifying its signature.
func ParseMLDSAWIT(token string) (*pqjose.Token, *MLDSAWITClaims, error) {
	tok, err := pqjose.ParseJWTWithTypes(token, "wit+jwt")
	if err != nil {
		return nil, nil, err
	}
	var claims MLDSAWITClaims
	if err := json.Unmarshal(tok.Claims(), &claims); err != nil {
		return nil, nil, fmt.Errorf("unable to parse WIT claims: %w", err)
	}
	return tok, &claims, nil
}
