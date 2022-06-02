package jwt

import (
	"encoding/json"
	"errors"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gin-gonic/gin"
)

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}
type JSONWebKeys struct {
	Alg string   `json:"alg"`
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

func GetJwtMiddleware() gin.HandlerFunc {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			cert, err := getCertificate(token)
			if err != nil {
				panic(err.Error())
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
	})

	return asGin(jwtMiddleware.Handler)
}

func asGin(middleware func(next http.Handler) http.Handler) gin.HandlerFunc {
	return func(gctx *gin.Context) {
		var skip = true
		var handler http.HandlerFunc = func(http.ResponseWriter, *http.Request) {
			skip = false
		}
		middleware(handler).ServeHTTP(gctx.Writer, gctx.Request)
		switch {
		case skip:
			gctx.Abort()
		default:
			gctx.Next()
		}
	}
}

func getCertificate(token *jwt.Token) (string, error) {
	cert := ""

	//This endpoint will contain the JWK used to verify all Auth0-issued JWTs for this tenant.
	resp, err := http.Get("dev-4l1tkzmy.eu.auth0.com/.well-known/jwks.json")
	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return cert, err
	}

	for key, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[key].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[key].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("Certificate key not found")
		return cert, err
	}

	return cert, nil
}
