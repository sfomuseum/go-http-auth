package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/sfomuseum/go-http-auth"
)

func main() {

	var authenticator_uri string
	var host string
	var port int

	flag.StringVar(&authenticator_uri, "authenticator-uri", "null://", "A registered sfomuseum/go-http-auth.Authenticator URI.")
	flag.StringVar(&host, "host", "localhost", "The host to listen for requests on.")
	flag.IntVar(&port, "port", 8080, "The port number to listen for requests on.")

	flag.Parse()

	ctx := context.Background()

	authenticator, err := auth.NewAuthenticator(ctx, authenticator_uri)

	if err != nil {
		log.Fatalf("Failed to create new authenticator, %v", err)
	}

	handler := debugHandler(authenticator)
	handler = authenticator.WrapHandler(handler)

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("Listening for requests at %s\n", addr)

	err = http.ListenAndServe(addr, mux)

	if err != nil {
		log.Fatalf("Failed to serve requests, %v", err)
	}
}

func debugHandler(authenticator auth.Authenticator) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		acct, err := authenticator.GetAccountForRequest(req)

		if err != nil {

			switch err.(type) {
			case auth.NotLoggedIn:
				slog.Error("Not logged in", "error", err)
				http.Error(rsp, "Forbidden", http.StatusForbidden)
				return
			default:
				slog.Error("Failed to derive account", "error", err)
				http.Error(rsp, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		msg := fmt.Sprintf("Hello, %s (%d)", acct.Name(), acct.Id())
		rsp.Write([]byte(msg))
		return
	}

	return http.HandlerFunc(fn)
}
