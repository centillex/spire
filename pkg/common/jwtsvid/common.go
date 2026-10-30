package jwtsvid

import (
	"errors"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

func GetTokenExpiry(token string) (time.Time, time.Time, error) {
	if _, claims, err := ParseMLDSAWIT(token); err == nil {
		if claims.IssuedAt == nil {
			return time.Time{}, time.Time{}, errors.New("JWT missing iat claim")
		}
		if claims.Expiry == nil {
			return time.Time{}, time.Time{}, errors.New("JWT missing exp claim")
		}
		return claims.IssuedAt.Time().UTC(), claims.Expiry.Time().UTC(), nil
	}
	if _, claims, _, err := ParseMLDSA(token); err == nil {
		if claims.IssuedAt == nil {
			return time.Time{}, time.Time{}, errors.New("JWT missing iat claim")
		}
		if claims.Expiry == nil {
			return time.Time{}, time.Time{}, errors.New("JWT missing exp claim")
		}
		return claims.IssuedAt.Time().UTC(), claims.Expiry.Time().UTC(), nil
	}

	tok, err := jwt.ParseSigned(token, AllowedSignatureAlgorithms)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	claims := jwt.Claims{}
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if claims.IssuedAt == nil {
		return time.Time{}, time.Time{}, errors.New("JWT missing iat claim")
	}
	if claims.Expiry == nil {
		return time.Time{}, time.Time{}, errors.New("JWT missing exp claim")
	}

	issuedAt := claims.IssuedAt.Time().UTC()
	expiresAt := claims.Expiry.Time().UTC()
	return issuedAt, expiresAt, nil
}
