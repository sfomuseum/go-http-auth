package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sfomuseum/runtimevar"
)

type JWTAuthenticatorClaims struct {
	AccountId   int64  `json:"account_id"`
	AccountName string `json:"account_name"`
	jwt.RegisteredClaims
}

var re_auth = regexp.MustCompile(`Bearer\s+((?:[a-ZA-Z0-9]+)\.(?:[a-ZA-Z0-9]+)\.(?:[a-ZA-Z0-9]+)$)`)

func init() {
	ctx := context.Background()
	RegisterAuthenticator(ctx, "jwt", NewJWTAuthenticator)
}

// type JWTAuthenticator implements the Authenticator interface to require a simple shared secret be passed
// with all requests. This is not a sophisticated handler. There are no nonces or hashing of requests or anything like
// that. It is a bare-bones supplementary authentication handler for environments that already implement their own
// measures of access control.
type JWTAuthenticator struct {
	Authenticator
	secret string
}

// NewJWTAuthenticator implements the Authenticator interface to ensure that requests contain a `X-Shared-Secret` HTTP
// header configured by 'uri' which is expected to take the form of:
//
//	sharedsecret://{SECRET}
//
// Where {SECRET} is expected to be the shared secret passed by HTTP requests.
func NewJWTAuthenticator(ctx context.Context, uri string) (Authenticator, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse URI, %w", err)
	}

	secret := u.Host

	if secret == "runtimevar" {

		q := u.Query()
		runtimevar_uri := q.Get("runtimevar-uri")

		s, err := runtimevar.StringVar(ctx, runtimevar_uri)

		if err != nil {
			return nil, fmt.Errorf("Failed to derive secret from runtimevar, %w", err)
		}

		secret = s
	}

	if secret == "" {
		return nil, fmt.Errorf("Missing or invalid secret")
	}
	
	a := &JWTAuthenticator{
		secret: secret,
	}

	return a, nil
}

// WrapHandler returns
func (a *JWTAuthenticator) WrapHandler(next http.Handler) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		_, err := a.GetAccountForRequest(req)

		if err != nil {
			http.Error(rsp, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(rsp, req)
		return
	}

	return http.HandlerFunc(fn)
}

// GetAccountForRequest returns an stub `Account` instance for requests that contain a valid `X-Shared-Secret` HTTP header.
func (a *JWTAuthenticator) GetAccountForRequest(req *http.Request) (Account, error) {

	var acct Account

	auth_header := req.Header.Get("Authorization")

	if re_auth.MatchString(auth_header) {
		return nil, fmt.Errorf("Invalid auth header")
	}

	m := re_auth.FindStringSubmatch(auth_header)
	str_token := m[1]

	token, err := jwt.Parse(str_token, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.secret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	if err != nil {
		return nil, err
	} else if claims, ok := token.Claims.(*JWTAuthenticatorClaims); ok {
		acct = NewAccount(claims.AccountId, claims.AccountName)
	} else {
		return nil, fmt.Errorf("Unknown claims type, cannot proceed")
	}

	return acct, nil
}

// SigninHandler returns an `http.Handler` instance that returns an HTTP "501 Not implemented" error.
func (a *JWTAuthenticator) SigninHandler() http.Handler {
	return notImplementedHandler()
}

// SignoutHandler returns an `http.Handler` instance that returns an HTTP "501 Not implemented" error.
func (a *JWTAuthenticator) SignoutHandler() http.Handler {
	return notImplementedHandler()
}

// SignoutHandler returns an `http.Handler` instance that returns an HTTP "501 Not implemented" error.
func (a *JWTAuthenticator) SignupHandler() http.Handler {
	return notImplementedHandler()
}
