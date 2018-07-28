package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	jwtverifier "github.com/caleblloyd/okta-jwt-verifier-golang"
)

type config struct {
	clientID         string
	clientSecret     string
	issuer           string
	tokenName        string
	loginRedirectURL string
	listenPort       string
	listenAddress    string
	oktaLoginBaseURL string
	requestTimeout   time.Duration
}

var conf config
var verifier *jwtverifier.JwtVerifier

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

	clientSecret := os.Getenv("CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatalln("Must specify CLIENT_SECRET env variable - These can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.")
	}

	issuer := strings.TrimRight(os.Getenv("ISSUER"), "/")
	if issuer == "" {
		log.Fatalln("This is the URL of the authorization server that will perform authentication. All Developer Accounts have a 'default' authorization server. The issuer is a combination of your Org URL (found in the upper right of the console home page) and /oauth2/default. For example, https://dev-1234.oktapreview.com/oauth2/default.")
	}

	loginRedirectURL := os.Getenv("LOGIN_REDIRECT_URL")
	if loginRedirectURL == "" {
		log.Fatalln("Must specify LOGIN_REDIRECT_URL env variable - These can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.")
	}

	oktaLoginBaseURL := issuer + "/v1/authorize" +
		"?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(loginRedirectURL) +
		"&response_type=code" +
		"&scope=openid" +
		"&nonce=123"

	toValidate := map[string]string{}
	toValidate["aud"] = "api://default"
	toValidate["cid"] = clientID

	jwtverifierSetup := jwtverifier.JwtVerifier{
		Issuer:           issuer,
		ClaimsToValidate: toValidate,
	}
	verifier = jwtverifierSetup.New()

	conf = config{
		clientID:         clientID,
		clientSecret:     clientSecret,
		loginRedirectURL: loginRedirectURL,
		issuer:           issuer,
		oktaLoginBaseURL: oktaLoginBaseURL,
		tokenName:        "okta-jwt",
	}
}

func main() {

	http.HandleFunc("/", validateCookieHandler)
	// cookie validation
	// if no cookie, redirect to okta
	// if cookie, valiate jwt with https://github.com/caleblloyd/okta-jwt-verifier-golang
	// if jwt valid return 200
	// if jwt not valide, return 401 with "X-Authorize-Redirect" with the Okta Authorize URL
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
		w.Header().Set("X-Authorize-Redirect", conf.oktaLoginBaseURL+"&state="+url.QueryEscape(r.URL.RequestURI()))
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("No Cookie")
		log.Printf("X-Authorize-Redirect,  %v", w.Header().Get("X-Authorize-Redirect"))
		return
	case err != nil:
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("Error parsing cookie,  %v", err)
		return
	}

	_, err = verifier.VerifyAccessToken(tokenCookie.Value)

	if err != nil {
		w.Header().Set("X-Authorize-Redirect", conf.oktaLoginBaseURL+"&state="+url.QueryEscape(r.URL.RequestURI()))
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("JWT Validation Error,  %v", err)
		log.Printf("X-Authorize-Redirect,  %v", w.Header().Get("X-Authorize-Redirect"))
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

	jwt, err := getJWT(code)
	if err != nil {
		http.Redirect(w, r, "/sso/error?error="+url.QueryEscape(err.Error()), http.StatusTemporaryRedirect)
		return
	}

	_, err = verifier.VerifyAccessToken(jwt)
	if err != nil {
		log.Printf("JWT Validation Error,  %v", err)
		http.Redirect(w, r, "/sso/error?error="+url.QueryEscape(err.Error()), http.StatusTemporaryRedirect)
		return
	}

	cookie := &http.Cookie{
		Name:     conf.tokenName,
		Value:    jwt,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

	state := params.Get("state")
	if state == "" {
		state = "/"
	}

	http.Redirect(w, r, state, http.StatusTemporaryRedirect)
}

type jwtResponse struct {
	AccessToken string `json:"access_token"`
}

func getJWT(code string) (string, error) {
	client := &http.Client{
		Timeout: time.Second * conf.requestTimeout,
	}
	reqBody := []byte("code=" + url.QueryEscape(code) +
		"&client_id=" + url.QueryEscape(conf.clientID) +
		"&client_secret=" + url.QueryEscape(conf.clientSecret) +
		"&redirect_uri=" + url.QueryEscape(conf.loginRedirectURL) +
		"&grant_type=authorization_code" +
		"&scope=openid")
	req, err := http.NewRequest("POST", conf.issuer+"/v1/token", bytes.NewBuffer(reqBody))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode == http.StatusOK {
		jsonResponse := &jwtResponse{}
		err = json.Unmarshal(bodyBytes, &jsonResponse)
		if err != nil {
			return "", err
		}
		return jsonResponse.AccessToken, nil
	}

	bodyStr := string(bodyBytes)
	return "", errors.New(bodyStr)
}
