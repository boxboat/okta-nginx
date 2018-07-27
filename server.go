package main

import (
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/caleblloyd/okta-jwt-verifier-golang"
)

type config struct {
	client_id   string
	issuer      string
	tokenName   string
	redirectURL string
}

var conf config

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

func init() {
	client_id := os.Getenv("CLIENT_ID")
	if client_id == "" {
		log.Fatalln("Must specify CLIENT_ID env variable - These can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.")
	}

	issuer := os.Getenv("ISSUER")
	if issuer == "" {
		log.Fatalln("This is the URL of the authorization server that will perform authentication. All Developer Accounts have a 'default' authorization server. The issuer is a combination of your Org URL (found in the upper right of the console home page) and /oauth2/default. For example, https://dev-1234.oktapreview.com/oauth2/default.")
	}

	conf := config{
		client_id: client_id,
		issuer:    issuer,
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
		// if error, redirect to "/sso/error?error={error string}"
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

func validateCookieHandler(w http.ResponseWriter, r *http.Request) {
	tokenCookie, err := r.Cookie(conf.tokenName)
	switch {
	case err == http.ErrNoCookie:
		log.Println("No cookie, redirecting to %s for auth", conf.redirectURL)
		http.Redirect(w, r, conf.redirectURL, http.StatusPermanentRedirect)
		return
	case err != nil:
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("Error parsing cookie,  %v", err)
		return
	}

	toValidate := map[string]string{}

	jwtverifierSetup := jwtverifier.JwtVerifier{
		Issuer:           conf.issuer,
		ClaimsToValidate: toValidate,
	}

	verifier := jwtverifierSetup.New()
	token, err := verifier.VerifyAccessToken(tokenCookie.String())

}
