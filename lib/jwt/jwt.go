package jwt

import (
	"dm_auth_srv/constant"
	authSrvPb "dm_auth_srv/proto/auth"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	jwtSecret = constant.JwtSecret
	myissuer  = constant.Myissuer
	ExpiresAt = constant.ExpiresAt
)

type Claims struct {
	jwt.StandardClaims
	JwtSession authSrvPb.Token
}

// 生成token字符串
func CreateToken(JwtSession authSrvPb.Token) (tokenString string, err error) {
	nowTime := time.Now()
	expireTime := nowTime.Add(ExpiresAt)

	claims := Claims{
		jwt.StandardClaims{
			ExpiresAt: expireTime.Unix(),
			Issuer:    myissuer,
		},
		JwtSession,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(jwtSecret)
	return
}

// 解析token字符串
func ParseToken(token string) (*Claims, error) {
	tokenClaims, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if tokenClaims != nil {
		if claims, ok := tokenClaims.Claims.(*Claims); ok && tokenClaims.Valid {
			return claims, nil
		}
	}

	return nil, err
}
