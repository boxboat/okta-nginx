package main

import (
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/caleblloyd/okta-jwt-verifier-golang"
)

type config struct {
	clientID       string
	clientSecret   string
	issuer         string
	tokenName      string
	redirectURL    string
	listenPort     string
	listenAddress  string
	oktaURL        string //Make sure this is https
	requestTimeout time.Duration
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
	clientID := os.Getenv("CLIENT_ID")
	if clientID == "" {
		log.Fatalln("Must specify CLIENT_ID env variable - These can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.")
	}

	issuer := os.Getenv("ISSUER")
	if issuer == "" {
		log.Fatalln("This is the URL of the authorization server that will perform authentication. All Developer Accounts have a 'default' authorization server. The issuer is a combination of your Org URL (found in the upper right of the console home page) and /oauth2/default. For example, https://dev-1234.oktapreview.com/oauth2/default.")
	}

	conf = config{
		clientID: clientID,
		issuer:   issuer,
	}
}

func main() {

	http.HandleFunc("/", validateCookieHandler)
	// cookie validation
	// if no cookie, redirect to okta
	// if cookie, valiate jwt with https://github.com/caleblloyd/okta-jwt-verifier-golang
	// if jwt valid return 200
	// if jwt not valide, return 403 with "X-Authorize-Redirect" with the Okta Authorize URL
	//log.Println(html.EscapeString(r.URL.Path))
	//fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	//})

	http.HandleFunc("/sso/authorization-code/callback", callbackHandler)
	// read the auth code from URL Param
	// call Okta to exchange Auth Code for JWT
	// set JWT in Cookie
	// if error, redirect to "/sso/error?error={error string}"

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
		log.Printf("No cookie, redirecting to %s for auth", conf.redirectURL)
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
	_, err = verifier.VerifyAccessToken(tokenCookie.String())

	if err != nil {
		w.Header().Set("X-Authorize-Redirect", conf.redirectURL)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if err == nil {
		w.WriteHeader(http.StatusOK)
	}
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	//Read auth code from URL Param
	params := r.URL.Query()
	code := params.Get("code")

	//Check for no code to guard against ddos
	if code == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func getJWT(code string) (string, error) {
	client := &http.Client{
		Timeout: time.Second * conf.requestTimeout,
	}
	req, err := http.NewRequest("POST", conf.oktaURL, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.URL.Query().Add("code", code)
	req.URL.Query().Add("client_id", conf.clientID)
	req.URL.Query().Add("client_secret", conf.clientSecret)
	req.URL.Query().Add("grant_type", "authorization_code")
	req.URL.Query().Add("scope", "openid")
	req.URL.Query().Add("redirect_uri", conf.redirectURL)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	bodyStr := string(bodyBytes)

	if resp.StatusCode == http.StatusOK {
		return bodyStr, nil
	}

	return "", errors.New(bodyStr)
}
