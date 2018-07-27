package main

import (
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
)

const sock = "/var/run/auth.sock"

func removeSockIfExists() {
	_, err := os.Stat(sock)
	if err == nil {
		err = os.Remove(sock)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// cookie validation
		// if no cookie, redirect to okta
		// if cookie, valiate jwt with https://github.com/caleblloyd/okta-jwt-verifier-golang
		// if jwt valid return 200
		// if jwt not valide, return 403 with "X-Authorize-Redirect" with the Okta Authorize URL
		log.Println(html.EscapeString(r.URL.Path))
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})

	http.HandleFunc("/sso/authorization-code/callback", func(w http.ResponseWriter, r *http.Request) {
		// read the auth code from URL Param
		// call Okta to exchange Auth Code for JWT
		// set JWT in Cookie
		// if error, return 403 with "X-Authorize-Error" with error Param
		log.Println(html.EscapeString(r.URL.Path))
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})

	removeSockIfExists()
	unixListener, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatal(err)
	}
	defer removeSockIfExists()

	if err = os.Chmod(sock, 0777); err != nil {
		log.Fatal(err)
	}

	http.Serve(unixListener, nil)
}
