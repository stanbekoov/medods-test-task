package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"medods-test/db"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	SECRET              = []byte("SECRET")
	ErrMismatchedTokens = errors.New("tokens have different session id`s")
	ErrClaims           = errors.New("token claims parsing error")
)

type Claims struct {
	jwt.RegisteredClaims
	IP        string `json:"ip"`
	SessionId string `json:"session"`
}

func createAccessToken(userId, ip, sesionId string) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userId,
			IssuedAt:  &jwt.NumericDate{Time: time.Now()},
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(30 * time.Second)},
		},
		IP:        ip,
		SessionId: sesionId,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token.SignedString(SECRET)
}

func createRefreshToken(userId, ip, sesionId string) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userId,
			IssuedAt:  &jwt.NumericDate{Time: time.Now()},
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(5 * time.Minute)},
		},
		IP:        ip,
		SessionId: sesionId,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token.SignedString(SECRET)
}

func CreateTokenPair(userId, ip, sesionId string) (string, string, error) {
	accessStr, err := createAccessToken(userId, ip, sesionId)
	if err != nil {
		return "", "", err
	}

	refreshStr, err := createRefreshToken(userId, ip, sesionId)
	if err != nil {
		return "", "", err
	}

	return accessStr, refreshStr, nil
}

func VerifyRefreshToken(refresh, uid string) (bool, error) {
	hashed, err := db.GetRefresh(uid)
	if err != nil {
		return false, err
	}

	hashedOther := sha256.Sum256([]byte(refresh))
	encoded := base64.StdEncoding.EncodeToString(hashedOther[:])

	return encoded == hashed, nil
}

func ParseToken(token string) (*jwt.Token, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	t, err := parser.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return SECRET, nil
	})

	if err != nil {
		return nil, err
	}

	_, err = t.Claims.GetExpirationTime()
	if err != nil {
		return nil, err
	}

	if _, ok := t.Claims.(*Claims); !ok {
		return nil, ErrClaims
	}

	return t, err
}

func RefreshTokenPair(access, refresh *jwt.Token, uid string) (string, string, error) {
	if refresh.Claims.(*Claims).SessionId != access.Claims.(*Claims).SessionId {
		return "", "", ErrMismatchedTokens
	}

	exp, err := refresh.Claims.GetExpirationTime()
	if err != nil {
		return "", "", err
	}

	if exp.Before(time.Now()) {
		return CreateTokenPair(uid, refresh.Claims.(*Claims).IP, refresh.Claims.(*Claims).SessionId)
	}

	accessStr, err := createAccessToken(uid, refresh.Claims.(*Claims).IP, refresh.Claims.(*Claims).SessionId)
	if err != nil {
		return "", "", err
	}

	refreshStr, err := refresh.SigningString()
	if err != nil {
		return "", "", err
	}

	return accessStr, refreshStr, nil
}
