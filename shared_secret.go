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

// re_auth is a regular expression used to match HTTP `Authorization` headers.
var re_auth *regexp.Regexp

func init() {
	ctx := context.Background()
	RegisterAuthenticator(ctx, "sharedsecret", NewSharedSecretAuthenticator)
	re_auth = regexp.MustCompile(`^X-Shared\s+(\w+)`)
}

// type SharedSecretAuthenticator implements the Authenticator interface to require a simple shared secret be passed
// with all requests. This is not a sophisticated handler. There are no nonces or hashing of requests or anything like
// that. It is a bare-bones supplementary authentication handler for environments that already implement their own
// measures of access control.
type SharedSecretAuthenticator struct {
	Authenticator
	secret string
	logger *log.Logger
}

// NewSharedSecretAuthenticator implements the Authenticator interface to ensure that requests contain a `X-Shared` HTTP `Authorization`
// header configured by 'uri' which is expected to take the form of:
//
//	sharedsecret://{SECRET}
//
// Where {SECRET} is expected to be the shared secret passed by HTTP requests.
func NewSharedSecretAuthenticator(ctx context.Context, uri string) (Authenticator, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse URI, %w", err)
	}

	secret := u.Host

	if secret == "" {
		return nil, fmt.Errorf("Missing or invalid secret")
	}

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
			// log.Println(err)
			http.Error(rsp, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(rsp, req)
		return
	}

	return http.HandlerFunc(fn)
}

// GetAccountForRequest returns an stub `Account` instance for requests that contain a valid `Authorization: X-Shared` header.
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

// SetLogger assign 'logger' to `a`.
func (a *SharedSecretAuthenticator) SetLogger(logger *log.Logger) {
	a.logger = logger
}
