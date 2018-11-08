package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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

type config struct {
	appOrigin         string        //computed
	clientID          string        //CLIENT_ID
	clientSecret      string        //CLIENT_SECRET
	cookieName        string        //computed
	issuer            string        //ISSUER
	loginRedirectPath string        //computed
	loginRedirectURL  string        //LOGIN_REDIRECT_URL
	oktaLoginBaseURL  string        //computed
	oktaOrigin        string        //computed
	ssoPath           string        //SSO_PATH
	requestTimeout    time.Duration //Default of 5 seconds if no env set
	verifier          *jwtverifier.JwtVerifier
}

type jwtResponse struct {
	AccessToken string `json:"access_token"`
}

func getConfig() *config {
	//Populate config from env vars
	clientID := os.Getenv("CLIENT_ID")
	if clientID == "" {
		log.Fatalln("Must specify CLIENT_ID env variable - Client ID can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.")
	}

	clientSecret := os.Getenv("CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatalln("Must specify CLIENT_SECRET env variable - Client Secret be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.")
	}

	issuer := strings.TrimRight(os.Getenv("ISSUER"), "/")
	if issuer == "" {
		log.Fatalln("This is the URL of the authorization server that will perform authentication. All Developer Accounts have a 'default' authorization server. The issuer is a combination of your Org URL (found in the upper right of the console home page) and /oauth2/default. For example, https://dev-1234.oktapreview.com/oauth2/default.")
	}
	
	audience := os.Getenv("AUDIENCE")
	if audience == "" {
		log.Fatalln("Must specify AUDIENCE env variable - Audience can be found on the 'Settings' tab of the Authorization Server.  The 'default' authorization server uses the audience 'api://default'")
	}
	
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		log.Fatalf("ISSUER is not a valid URL, %v", issuer)
	}

	loginRedirect := os.Getenv("LOGIN_REDIRECT_URL")
	if loginRedirect == "" {
		log.Fatalln("Must specify LOGIN_REDIRECT_URL env variable - These can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.")
	}
	loginRedirectURL, err := url.Parse(loginRedirect)
	if err != nil {
		log.Fatalf("LOGIN_REDIRECT_URL is not a valid URL, %v", loginRedirect)
	}

	ssoPath := os.Getenv("SSO_PATH")
	if ssoPath == "" {
		ssoPath = "/sso/"
	} else {
		ssoPath = "/" + strings.Trim(ssoPath, "/") + "/"
	}

	cookieName := os.Getenv("COOKIE_NAME")
	if cookieName == "" {
		cookieName = "okta-jwt"
	}

	requestTimeOutDuration := time.Duration(5)
	requestTimeOut := os.Getenv("REQUEST_TIMEOUT")
	if requestTimeOut != "" {
		requestTimeoutInt, err := strconv.Atoi(os.Getenv("REQUEST_TIMEOUT"))
		if err != nil {
			log.Println("Unable to parse REQUEST_TIMEOUT env variable, using a default of 5 seconds")
		} else {
			requestTimeOutDuration = time.Duration(requestTimeoutInt)
		}
	}

	appOrigin := loginRedirectURL.Scheme + "://" + loginRedirectURL.Host
	oktaOrigin := issuerURL.Scheme + "://" + issuerURL.Host

	//Initialize validator
	toValidate := map[string]string{}
	toValidate["aud"] = audience
	toValidate["cid"] = clientID

	jwtverifierSetup := jwtverifier.JwtVerifier{
		Issuer:           issuer,
		ClaimsToValidate: toValidate,
	}

	oktaLoginBaseURL := issuer + "/v1/authorize" +
		"?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(loginRedirect) +
		"&response_type=code" +
		"&scope=openid profile" +
		"&nonce=123"

	return &config{
		appOrigin:         appOrigin,
		clientID:          clientID,
		clientSecret:      clientSecret,
		cookieName:        cookieName,
		issuer:            issuer,
		loginRedirectPath: loginRedirectURL.Path,
		loginRedirectURL:  loginRedirect,
		oktaLoginBaseURL:  oktaLoginBaseURL,
		oktaOrigin:        oktaOrigin,
		requestTimeout:    requestTimeOutDuration,
		ssoPath:           ssoPath,
		verifier:          jwtverifierSetup.New(),
	}
}

func main() {
	runServer(getConfig())
}

func runServer(conf *config) {

	//Validate cookie on each request
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		validateCookieHandler(w, r, conf)
	})

	//Authorization code callback
	http.HandleFunc(conf.loginRedirectPath, func(w http.ResponseWriter, r *http.Request) {
		callbackHandler(w, r, conf)
	})

	//Refresh check
	http.HandleFunc(conf.ssoPath+"refresh/check", func(w http.ResponseWriter, r *http.Request) {
		refreshCheckHandler(w, r, conf)
	})

	//Refresh done
	http.HandleFunc(conf.ssoPath+"refresh/done", func(w http.ResponseWriter, r *http.Request) {
		refreshDoneHandler(w, r, conf)
	})

	//Error
	http.HandleFunc(conf.ssoPath+"error", func(w http.ResponseWriter, r *http.Request) {
		errorHandler(w, r, conf)
	})

	//Listen on unix socket instead of http
	removeSockIfExists()
	unixListener, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatal(err)
	}
	defer removeSockIfExists()

	if err = os.Chmod(sock, 0666); err != nil {
		log.Fatal(err)
	}

	err = http.Serve(unixListener, nil)
	if err != nil {
		log.Fatalf("Error serving on socket, err: %v", err)
	}
}

//validateCookieHandler calls the okta api to validate the cookie
func validateCookieHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	redirectURL := conf.oktaLoginBaseURL + "&state=" + url.QueryEscape(r.URL.RequestURI())

	// initialize headers
	w.Header().Set("X-Auth-Request-Redirect", "")
	w.Header().Set("X-Auth-Request-User", "")

	tokenCookie, err := r.Cookie(conf.cookieName)
	switch {
	case err == http.ErrNoCookie:
		w.Header().Set("X-Auth-Request-Redirect", redirectURL)
		w.WriteHeader(http.StatusUnauthorized)
		return
	case err != nil:
		log.Printf("validateCookieHandler: Error parsing cookie, %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwt, err := conf.verifier.VerifyAccessToken(tokenCookie.Value)

	if err != nil {
		w.Header().Set("X-Auth-Request-Redirect", redirectURL)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	sub, ok := jwt.Claims["sub"]
	if !ok {
		log.Printf("validateCookieHandler: Claim 'sub' not included in access token, %v", tokenCookie.Value)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	subStr, ok := sub.(string)
	if !ok {
		log.Printf("validateCookieHandler: Unable to convert 'sub' to string")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("X-Auth-Request-User", subStr)
	w.WriteHeader(http.StatusOK)
}

func callbackHandler(w http.ResponseWriter, r *http.Request, conf *config) {

	//Read auth code from URL Param
	params := r.URL.Query()
	code := params.Get("code")
	ssoErr := params.Get("error")

	unsetCookie := &http.Cookie{
		Name:     conf.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
	}

	//Redirect if error in param
	if ssoErr != "" {
		http.SetCookie(w, unsetCookie)
		http.Redirect(w, r, "/sso/error?error="+url.QueryEscape(ssoErr), http.StatusTemporaryRedirect)
		return
	}

	//Check for no code and no error to guard against ddos
	if code == "" {
		http.SetCookie(w, unsetCookie)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwt, err := getJWT(code, conf)
	//Redirect if error getting JWT
	if err != nil {
		log.Printf("callbackHandler: Error in getJWT, %v", err)
		http.SetCookie(w, unsetCookie)
		http.Redirect(w, r, "/sso/error?error="+url.QueryEscape(err.Error()), http.StatusTemporaryRedirect)
		return
	}

	_, err = conf.verifier.VerifyAccessToken(jwt)
	if err != nil {
		log.Printf("callbackHandler: JWT Validation Error, %v", err)
		http.SetCookie(w, unsetCookie)
		http.Redirect(w, r, "/sso/error?error="+url.QueryEscape(err.Error()), http.StatusTemporaryRedirect)
		return
	}

	//Set cookie if code valid
	cookie := &http.Cookie{
		Name:     conf.cookieName,
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

func refreshCheckHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	redirectURL := conf.oktaLoginBaseURL + "&prompt=none&state=/sso/refresh/done"

	tokenCookie, err := r.Cookie(conf.cookieName)
	switch {
	case err == http.ErrNoCookie:
		log.Printf("refreshHandler: No Cookie")
		w.WriteHeader(http.StatusUnauthorized)
		return
	case err != nil:
		log.Printf("refreshHandler: Error parsing cookie, %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwt, err := conf.verifier.VerifyAccessToken(tokenCookie.Value)

	if err != nil {
		log.Printf("refreshHandler: JWT Validation Error, %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	exp, ok := jwt.Claims["exp"]
	if !ok {
		log.Printf("refreshHandler: Claim 'exp' not included in access token, %v", tokenCookie.Value)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	expFloat, ok := exp.(float64)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("refreshHandler: Unable to convert 'exp' to float64")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if expFloat-float64(time.Now().UTC().Unix()) < (5 * time.Minute).Seconds() {
		_, err = io.WriteString(w, redirectURL)
	} else {
		_, err = io.WriteString(w, "ok")
	}

	if err != nil {
		log.Printf("refreshDoneHandler: error when writing string to output, %v", err)
		return
	}
}

func refreshDoneHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := io.WriteString(w, `
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>SSO Refresh</title>
			<script>
				window.parent.postMessage("ssoRefreshDone","`+conf.appOrigin+`");
			</script>
		</head>
		<body>
			SSO Refresh
		</body>
	</html> 
	`)

	if err != nil {
		log.Printf("refreshDoneHandler: error when writing string to output, %v", err)
		return
	}
}

func errorHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	params := r.URL.Query()
	ssoErr := params.Get("error")

	w.WriteHeader(http.StatusUnauthorized)

	_, err := io.WriteString(w, `
	<!DOCTYPE html>
	<html>
		<head>
			<title>Sign-On Error</title>
			<style>
				body {
					width: 35em;
					margin: 0 auto;
					font-family: Tahoma, Verdana, Arial, sans-serif;
				}
				pre {
					border: 1px solid #000;
					padding: 3px;
					background-color: #dedede;
				}
			</style>
		</head>
	<body>
		<h1>Sign-On Error</h1>
		<p>An error occurred with sign-on</p>
		
		<p><strong>Error Details:</strong></p>

		<pre>`+ssoErr+`</pre>
	</body>
	</html>	
	`)

	if err != nil {
		log.Printf("refreshDoneHandler: error when writing string to output, %v", err)
		return
	}
}

//getJWT queries the okta server with an access code.  A valid request will return a JWT access token.
func getJWT(code string, conf *config) (string, error) {
	client := &http.Client{
		Timeout: time.Second * conf.requestTimeout,
	}

	reqBody := []byte("code=" + url.QueryEscape(code) +
		"&client_id=" + url.QueryEscape(conf.clientID) +
		"&client_secret=" + url.QueryEscape(conf.clientSecret) +
		"&redirect_uri=" + url.QueryEscape(conf.loginRedirectURL) +
		"&grant_type=authorization_code" +
		"&scope=openid profile")

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

	//200 == authorization succeeded
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
