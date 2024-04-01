package auth

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
)

var re_auth *regexp.Regexp

func init() {
	ctx := context.Background()
	RegisterAuthenticator(ctx, "none", NewSharedSecretAuthenticator)

	re_auth = regexp.MustCompile(`Authorization:\s+Shared\s+(.*)`)
}

// type SharedSecretAuthenticator implements the Authenticator interface that always returns a "not authorized" error.
type SharedSecretAuthenticator struct {
	Authenticator
	secret string
	logger *log.Logger
}

// NewSharedSecretAuthenticator implements the Authenticator interface that always returns a "not authorized" error.
// configured by 'uri' which is expected to take the form of:
//
//	sharedsecret://{SECRET}
func NewSharedSecretAuthenticator(ctx context.Context, uri string) (Authenticator, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse URI, %w", err)
	}

	secret := u.Host

	logger := log.New(io.Discard, "", 0)

	a := &SharedSecretAuthenticator{
		secret: secret,
		logger: logger,
	}

	return a, nil
}

// WrapHandler returns
func (a *SharedSecretAuthenticator) WrapHandler(next http.Handler) http.Handler {

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

// GetAccountForRequest returns an stub `Account` instance.
func (a *SharedSecretAuthenticator) GetAccountForRequest(req *http.Request) (*Account, error) {

	auth := req.Header.Get("Authorization")

	if !re_auth.MatchString(auth) {
		return nil, fmt.Errorf("Missing or invalid Authorization header")
	}

	m := re_auth.FindStringSubmatch(auth)
	secret := m[1]

	if secret != a.secret {
		return nil, NotAuthorized{}
	}

	acct := &Account{
		Id:   -1,
		Name: "",
	}

	return acct, nil
}

// SigninHandler returns an `http.Handler` instance that returns an HTTP "501 Not implemented" error.
func (a *SharedSecretAuthenticator) SigninHandler() http.Handler {
	return notImplementedHandler()
}

// SignoutHandler returns an `http.Handler` instance that returns an HTTP "501 Not implemented" error.
func (a *SharedSecretAuthenticator) SignoutHandler() http.Handler {
	return notImplementedHandler()
}

// SignoutHandler returns an `http.Handler` instance that returns an HTTP "501 Not implemented" error.
func (a *SharedSecretAuthenticator) SignupHandler() http.Handler {
	return notImplementedHandler()
}

// SetLogger is a no-op and does nothing.
func (a *SharedSecretAuthenticator) SetLogger(logger *log.Logger) {
	a.logger = logger
}
