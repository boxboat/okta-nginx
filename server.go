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
	"strconv"
	"strings"
	"time"

	jwtverifier "github.com/caleblloyd/okta-jwt-verifier-golang"
)

const sock = "/var/run/auth.sock"
const tokenName = "okta-jwt"

type config struct {
	clientID         string        //CLIENT_ID
	clientSecret     string        //CLIENT_SECRET
	issuer           string        //ISSUER
	loginRedirectURL string        //LOGIN_REDIRECT_URL
	tokenName        string        //constant
	oktaLoginBaseURL string        //computed
	requestTimeout   time.Duration //Default of 5 seconds if no env set
	verifier         *jwtverifier.JwtVerifier
}

type jwtResponse struct {
	AccessToken string `json:"access_token"`
}

func getConfig() config {
	//Populate config from env vars
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

	requestTimeoutInt, err := strconv.Atoi(os.Getenv("REQUEST_TIMEOUT"))
	requestTimeOut := time.Duration(5)
	//Just youse 5 seconds if there is an error parsing
	if err == nil {
		log.Println("Unable to parse REQUEST_TIMEOUT environment variable, using a default of 5 seconds")
		requestTimeOut = time.Duration(requestTimeoutInt)
	}

	//Initialize validator
	toValidate := map[string]string{}
	toValidate["aud"] = "api://default"
	toValidate["cid"] = clientID

	jwtverifierSetup := jwtverifier.JwtVerifier{
		Issuer:           issuer,
		ClaimsToValidate: toValidate,
	}

	oktaLoginBaseURL := issuer + "/v1/authorize" +
		"?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(loginRedirectURL) +
		"&response_type=code" +
		"&scope=openid" +
		"&nonce=123"

	return config{
		clientID:         clientID,
		clientSecret:     clientSecret,
		loginRedirectURL: loginRedirectURL,
		issuer:           issuer,
		tokenName:        tokenName,
		requestTimeout:   requestTimeOut,
		verifier:         jwtverifierSetup.New(),
		oktaLoginBaseURL: oktaLoginBaseURL,
	}
}

func main() {
	runServer(getConfig())
}

func runServer(conf config) {

	//Validate cookie on each request
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		validateCookieHandler(w, r, conf)
	})

	//Authorization code callback
	http.HandleFunc("/sso/authorization-code/callback", func(w http.ResponseWriter, r *http.Request) {
		callbackHandler(w, r, conf)
	})

	//Listen on unix socket instead of http
	removeSockIfExists()
	unixListener, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatal(err)
	}
	defer removeSockIfExists()

	//might need to change owner of the socket
	if err = os.Chmod(sock, 0660); err != nil {
		log.Fatal(err)
	}

	err = http.Serve(unixListener, nil)
	if err != nil {
		log.Fatalf("Error serving on socket, err: %v", err)
	}
}

func validateCookieHandler(w http.ResponseWriter, r *http.Request, conf config) {
	redirectURL := conf.oktaLoginBaseURL + "&state=" + url.QueryEscape(r.URL.RequestURI())

	tokenCookie, err := r.Cookie(conf.tokenName)
	switch {
	case err == http.ErrNoCookie:
		w.Header().Set("X-Authorize-Redirect", redirectURL)
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("No Cookie")
		log.Printf("X-Authorize-Redirect,  %v", w.Header().Get("X-Authorize-Redirect"))
		return
	case err != nil:
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("Error parsing cookie,  %v", err)
		return
	}

	_, err = conf.verifier.VerifyAccessToken(tokenCookie.Value)

	if err != nil {
		w.Header().Set("X-Authorize-Redirect", redirectURL)
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("JWT Validation Error,  %v", err)
		log.Printf("X-Authorize-Redirect,  %v", w.Header().Get("X-Authorize-Redirect"))
		return
	}

	if err == nil {
		w.WriteHeader(http.StatusOK)
	}
}

func callbackHandler(w http.ResponseWriter, r *http.Request, conf config) {

	//Read auth code from URL Param
	params := r.URL.Query()
	code := params.Get("code")

	//Check for no code to guard against ddos
	if code == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//Redirtect if error
	jwt, err := getJWT(code, conf)
	if err != nil {
		http.Redirect(w, r, "/sso/error?error="+url.QueryEscape(err.Error()), http.StatusTemporaryRedirect)
		return
	}

	_, err = conf.verifier.VerifyAccessToken(jwt)
	if err != nil {
		log.Printf("JWT Validation Error,  %v", err)
		http.Redirect(w, r, "/sso/error?error="+url.QueryEscape(err.Error()), http.StatusTemporaryRedirect)
		return
	}

	//Set cokkie if code valid
	cookie := &http.Cookie{
		Name:     conf.tokenName,
		Value:    jwt,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

	//Redirect to requested page
	state := params.Get("state")
	if state == "" {
		state = "/"
	}

	http.Redirect(w, r, state, http.StatusTemporaryRedirect)
}

//getJWT queries the okta server with an access code.  A valid request will return a JWT access token.
func getJWT(code string, conf config) (string, error) {
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
	if err != nil {
		return "", err
	}
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

	//200 == authorization suceeded.
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

func removeSockIfExists() {
	_, err := os.Stat(sock)
	if err == nil {
		err = os.Remove(sock)
		if err != nil {
			log.Fatal(err)
		}
	}
}
