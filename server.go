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
	"sync"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
	jwtverifier "github.com/caleblloyd/okta-jwt-verifier-golang"
)

const sock = "/var/run/auth.sock"

type config struct {
	clientID            string        //CLIENT_ID
	clientSecret        string        //CLIENT_SECRET
	endpointAuthorize	string		  //ENDPOINT_AUTHORIZE
	endpointLogout      string        //ENDPOINT_LOGOUT
	endpointToken       string        //ENDPOINT_TOKEN
	issuer              string        //ISSUER
	ssoPath             string        //SSO_PATH
	requestTimeout      time.Duration //Default of 5 seconds if no env set
	verifier            *jwtverifier.JwtVerifier
}

var templateCache = make(map[string]*template.Template)
var templateCacheMu = &sync.Mutex{}

type jwtResponse struct {
	IDToken string `json:"id_token"`
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

	_, err := url.Parse(issuer)
	if err != nil {
		log.Fatalf("ISSUER is not a valid URL, %v", issuer)
	}

	ssoPath := os.Getenv("SSO_PATH")
	if ssoPath == "" {
		ssoPath = "/sso/"
	} else {
		ssoPath = "/" + strings.Trim(ssoPath, "/") + "/"
	}

	endpointAuthorize := os.Getenv("ENDPOINT_AUTHORIZE")
	if endpointAuthorize == "" {
		endpointAuthorize = issuer + "/v1/authorize"
	} else {
		_, err := url.Parse(issuer)
		if err != nil {
			log.Fatalf("ENDPOINT_AUTHORIZE is not a valid URL, %v", endpointAuthorize)
		}
	}

	endpointLogout := os.Getenv("ENDPOINT_LOGOUT")
	if endpointLogout == "" {
		endpointLogout = issuer + "/v1/logout"
	} else {
		_, err := url.Parse(issuer)
		if err != nil {
			log.Fatalf("ENDPOINT_LOGOUT is not a valid URL, %v", endpointLogout)
		}
	}

	endpointToken := os.Getenv("ENDPOINT_TOKEN")
	if endpointToken == "" {
		endpointToken = issuer + "/v1/token"
	} else {
		_, err := url.Parse(issuer)
		if err != nil {
			log.Fatalf("ENDPOINT_TOKEN is not a valid URL, %v", endpointToken)
		}
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

	//Initialize validator
	toValidate := map[string]string{}
	toValidate["iss"] = issuer
	toValidate["aud"] = clientID
	toValidate["nonce"] = "123"

	jwtverifierSetup := jwtverifier.JwtVerifier{
		Issuer:           issuer,
		ClaimsToValidate: toValidate,
	}

	return &config{
		clientID:            clientID,
		clientSecret:        clientSecret,
		endpointAuthorize:   endpointAuthorize,
		endpointLogout:      endpointLogout,
		endpointToken:       endpointToken,
		issuer:              issuer,
		requestTimeout:      requestTimeOutDuration,
		ssoPath:             ssoPath,
		verifier:            jwtverifierSetup.New(),
	}
}

func main() {
	runServer(getConfig())
}

func runServer(conf *config) {

	//Validate cookie on /auth/validate requests
	http.HandleFunc("/auth/validate", func(w http.ResponseWriter, r *http.Request) {
		validateCookieHandler(w, r, conf)
	})

	//Authorization code callback
	http.HandleFunc(conf.ssoPath+"authorization-code/callback", func(w http.ResponseWriter, r *http.Request) {
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

	//Logout
	http.HandleFunc(conf.ssoPath+"logout", func(w http.ResponseWriter, r *http.Request) {
		logoutHandler(w, r, conf)
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
	// initialize headers
	w.Header().Set("X-Auth-Request-Redirect", "")
	w.Header().Set("X-Auth-Request-User", "")

	tokenCookie, err := r.Cookie(getCookieName(r))
	switch {
	case err == http.ErrNoCookie:
		w.Header().Set("X-Auth-Request-Redirect", redirectURL(r, conf, r.Header.Get("X-Okta-Nginx-Request-Uri")))
		w.WriteHeader(http.StatusUnauthorized)
		return
	case err != nil:
		log.Printf("validateCookieHandler: Error parsing cookie, %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwt, err := conf.verifier.VerifyIdToken(tokenCookie.Value)

	if err != nil {
		w.Header().Set("X-Auth-Request-Redirect", redirectURL(r, conf, r.Header.Get("X-Okta-Nginx-Request-Uri")))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	username, ok := jwt.Claims["preferred_username"]
	if !ok {
		log.Printf("validateCookieHandler: Claim 'preferred_username' not included in access token, %v", tokenCookie.Value)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	usernameStr, ok := username.(string)
	if !ok {
		log.Printf("validateCookieHandler: Unable to convert 'preferred_username' to string in access token, %v", tokenCookie.Value)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	validateClaimsTemplate := strings.TrimSpace(r.Header.Get("X-Okta-Nginx-Validate-Claims-Template"))
	if validateClaimsTemplate != "" {
		t, err := getTemplate(validateClaimsTemplate)
		if err != nil {
			log.Printf("validateCookieHandler: validateClaimsTemplate failed to parse template: '%v', error: %v", validateClaimsTemplate, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var resultBytes bytes.Buffer
		if err := t.Execute(&resultBytes, jwt.Claims); err != nil {
			claimsJSON, _ := json.Marshal(jwt.Claims)
			log.Printf("validateCookieHandler: validateClaimsTemplate failed to execute template: '%v', data: '%v', error: '%v'", validateClaimsTemplate, claimsJSON, err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resultString := strings.ToLower(strings.TrimSpace(resultBytes.String()))

		if resultString != "true" && resultString != "1" {
			log.Printf("validateCookieHandler: validateClaimsTemplate template: '%v', result: '%v', preferred_username: '%v'", validateClaimsTemplate, resultString, usernameStr)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	setHeaderNames := strings.Split(r.Header.Get("X-Okta-Nginx-Proxy-Set-Header-Names"), ",")
	setHeaderValues := strings.Split(r.Header.Get("X-Okta-Nginx-Proxy-Set-Header-Values"), ",")
	if setHeaderNames[0] != "" && setHeaderValues[0] != "" && len(setHeaderNames) == len(setHeaderValues) {
		for i := 0; i < len(setHeaderNames); i++ {
			t, err := getTemplate(setHeaderValues[i])
			if err != nil {
				log.Printf("validateCookieHandler: setHeaderValues failed to parse template: '%v', error: %v", validateClaimsTemplate, err)
				continue
			}

			var resultBytes bytes.Buffer
			if err := t.Execute(&resultBytes, jwt.Claims); err != nil {
				claimsJSON, _ := json.Marshal(jwt.Claims)
				log.Printf("validateCookieHandler: setHeaderValues failed to execute template: '%v', data: '%v', error: '%v'", validateClaimsTemplate, claimsJSON, err)
				continue
			}
			resultString := strings.ToLower(strings.TrimSpace(resultBytes.String()))

			w.Header().Set(setHeaderNames[i], resultString)
		}
	}

	w.Header().Set("X-Auth-Request-User", usernameStr)
	w.WriteHeader(http.StatusOK)
}

func callbackHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	//Read auth code from URL Param
	params := r.URL.Query()
	code := params.Get("code")
	ssoErr := params.Get("error")

	unsetCookie := &http.Cookie{
		Domain:   getCookieDomain(r),
		Name:     getCookieName(r),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
	}

	//Redirect if error in param
	if ssoErr != "" {
		http.SetCookie(w, unsetCookie)
		http.Redirect(w, r, getRequestOriginURL(r).String()+conf.ssoPath+"error?error="+url.QueryEscape(ssoErr), http.StatusTemporaryRedirect)
		return
	}

	//Check for no code and no error to guard against ddos
	if code == "" {
		http.SetCookie(w, unsetCookie)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwtStr, err := getJWT(r, code, conf)
	//Redirect if error getting JWT
	if err != nil {
		log.Printf("callbackHandler: Error in getJWT, %v", err)
		http.SetCookie(w, unsetCookie)
		http.Redirect(w, r, getRequestOriginURL(r).String()+conf.ssoPath+"error?error="+url.QueryEscape(err.Error()), http.StatusTemporaryRedirect)
		return
	}

	jwt, err := conf.verifier.VerifyIdToken(jwtStr)
	if err != nil {
		log.Printf("refreshHandler: JWT Validation Error, %v", err)
		http.SetCookie(w, unsetCookie)
		http.Redirect(w, r, getRequestOriginURL(r).String()+conf.ssoPath+"error?error="+url.QueryEscape(err.Error()), http.StatusTemporaryRedirect)
		return
	}

	exp, ok := jwt.Claims["exp"]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("refreshHandler: Claim 'exp' not included in access token, %v", jwtStr)
		return
	}

	expFloat, ok := exp.(float64)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("refreshHandler: Unable to convert 'exp' to float64")
		return
	}

	//Set cookie if code valid
	cookie := &http.Cookie{
		Domain:   getCookieDomain(r),
		Expires:  time.Unix(int64(expFloat), 0),
		Name:     getCookieName(r),
		Value:    jwtStr,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

	//Redirect to requested page
	requestOrigin := getRequestOriginURL(r).String()
	state := params.Get("state")

	stateURL, err := url.Parse(state)
	if err != nil {
		log.Printf("refreshHandler: state paramater '%v' is not a valid URL", state)
		http.Redirect(w, r, requestOrigin+conf.ssoPath+"error?error="+url.QueryEscape("Unauthorized"), http.StatusTemporaryRedirect)
		return
	}

	if (stateURL.Scheme != "" || stateURL.Host != "") && !urlMatchesCookieDomain(stateURL, getCookieDomain(r)) {
		log.Printf("refreshHandler: state paramater '%v' is not valid for COOKIE_DOMAIN '%v'", state, getCookieDomain(r))
		http.Redirect(w, r, requestOrigin+conf.ssoPath+"error?error="+url.QueryEscape("Unauthorized"), http.StatusTemporaryRedirect)
		return
	}

	http.Redirect(w, r, state, http.StatusTemporaryRedirect)
}

func refreshCheckHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	tokenCookie, err := r.Cookie(getCookieName(r))
	switch {
	case err == http.ErrNoCookie:
		log.Printf("refreshCheckHandler: No Cookie")
		w.WriteHeader(http.StatusUnauthorized)
		return
	case err != nil:
		log.Printf("refreshCheckHandler: Error parsing cookie, %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwt, err := conf.verifier.VerifyIdToken(tokenCookie.Value)

	if err != nil {
		log.Printf("refreshCheckHandler: JWT Validation Error, %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	exp, ok := jwt.Claims["exp"]
	if !ok {
		log.Printf("refreshCheckHandler: Claim 'exp' not included in access token, %v", tokenCookie.Value)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	expFloat, ok := exp.(float64)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("refreshCheckHandler: Unable to convert 'exp' to float64")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if expFloat-float64(time.Now().UTC().Unix()) < (5 * time.Minute).Seconds() {
		_, err = io.WriteString(w, redirectURL(r, conf, conf.ssoPath+"refresh/done"))
	} else {
		_, err = io.WriteString(w, "ok")
	}

	if err != nil {
		log.Printf("refreshCheckHandler: error when writing string to output, %v", err)
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
				window.parent.postMessage("ssoRefreshDone", window.location.protocol + "//" + window.location.host);
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

func logoutHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	unsetCookie := &http.Cookie{
		Domain:   getCookieDomain(r),
		Name:     getCookieName(r),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
	}

	logoutRedirect := getLogoutRedirectURL(r).String()
	tokenCookie, err := r.Cookie(unsetCookie.Name)
	if err != nil {
		http.Redirect(w, r, logoutRedirect, http.StatusTemporaryRedirect)
	}

	http.SetCookie(w, unsetCookie)
	http.Redirect(w, r,
		conf.endpointLogout +
			"?id_token_hint=" + url.QueryEscape(tokenCookie.Value) +
			"&post_logout_redirect_uri=" + url.QueryEscape(logoutRedirect),
		http.StatusTemporaryRedirect)
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
		log.Printf("errorHandler: error when writing string to output, %v", err)
		return
	}
}

//getJWT queries the okta server with an access code.  A valid request will return a JWT access token.
func getJWT(r *http.Request, code string, conf *config) (string, error) {
	client := &http.Client{
		Timeout: time.Second * conf.requestTimeout,
	}

	loginRedirect := getLoginRedirectURL(r).String()
	reqBody := []byte("code=" + url.QueryEscape(code) +
		"&client_id=" + url.QueryEscape(conf.clientID) +
		"&client_secret=" + url.QueryEscape(conf.clientSecret) +
		"&redirect_uri=" + url.QueryEscape(loginRedirect) +
		"&grant_type=authorization_code" +
		"&scope=openid profile")

	req, err := http.NewRequest("POST", conf.endpointToken, bytes.NewBuffer(reqBody))
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
		return jsonResponse.IDToken, nil
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

func urlMatchesCookieDomain(matchURL *url.URL, cookieDomain string) bool {
	return cookieDomain == "" || matchURL.Hostname() == cookieDomain || strings.HasSuffix(matchURL.Hostname(), "."+cookieDomain)
}

func redirectURL(r *http.Request, conf *config, requestURI string) string {
	requestURLStr := requestURI
	requestOriginURL := getRequestOriginURL(r)
	if requestOriginURL == nil {
		log.Printf("redirectURL: redirect will not include origin")
	} else {
		if urlMatchesCookieDomain(requestOriginURL, getCookieDomain(r)) {
			requestURLStr = requestOriginURL.String() + requestURLStr
		} else {
			log.Printf("redirectURL: header 'X-Forwarded-Host' hostname '%v' is not valid for COOKIE_DOMAIN '%v'", requestOriginURL.Hostname(), getCookieDomain(r))
			log.Printf("redirectURL: redirect will not include origin")
		}
	}

	appPostLoginURL := getAppPostLoginURL(r)
	if appPostLoginURL != nil {
		appPostLoginStruct := *appPostLoginURL
		appPostLoginURL := &appPostLoginStruct
		q := appPostLoginURL.Query()
		q.Set("state", requestURLStr)
		appPostLoginURL.RawQuery = q.Encode()
		requestURLStr = appPostLoginURL.String()
	}

	loginRedirect := getLoginRedirectURL(r).String()
	return conf.endpointAuthorize + 
		"?client_id=" + url.QueryEscape(conf.clientID) +
		"&response_type=code" +
		"&scope=openid profile" +
		"&nonce=123" +
		"&redirect_uri=" + url.QueryEscape(loginRedirect)  + 
		"&state=" + url.QueryEscape(requestURLStr)
}

func getAppPostLoginURL(r *http.Request) *url.URL {
	appPostLogin := os.Getenv("APP_POST_LOGIN_URL")
	if appPostLogin != "" {
		appPostLoginURL, err := url.Parse(appPostLogin)
		if err != nil {
			log.Printf("APP_POST_LOGIN_URL is not a valid URL, %v", appPostLogin)
			return nil
		}
		return appPostLoginURL
	}
	return nil
}

func getRequestOriginURL(r *http.Request) *url.URL {
	requestScheme := r.Header.Get("X-Forwarded-Proto")
	requestHost := r.Header.Get("X-Forwarded-Host")
	if requestScheme != "" && requestHost != "" {
		requestOrigin := requestScheme + "://" + requestHost
		requestOriginURL, err := url.Parse(requestOrigin)
		if err != nil {
			log.Printf("getRequestOriginURL: headers 'X-Forwarded-Proto' and 'X-Forwarded-Host' form invalid origin '%v'", requestOrigin)
			return &url.URL{}
		}
		return requestOriginURL
	}
	log.Printf("getRequestOriginURL: headers 'X-Forwarded-Proto' and/or 'X-Forwarded-Host' not set")
	return &url.URL{}
}

func getCookieName(r *http.Request) string{
	cookieName := r.Header.Get("X-Okta-Nginx-Cookie-Name")
	if cookieName == "" {
		cookieName = "okta-jwt"
	}
	return cookieName
}

func getCookieDomain(r *http.Request) string {
	return strings.TrimLeft(r.Header.Get("X-Okta-Nginx-Cookie-Domain"), ".")
}

func getLoginRedirectURL(r *http.Request) *url.URL {
	loginRedirect := r.Header.Get("X-Okta-Nginx-Login-Redirect-Url")
	if loginRedirect == "" {
		log.Printf("Must specify LOGIN_REDIRECT_URL env variable - These can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.")
		return &url.URL{}
	}
	loginRedirectURL, err := url.Parse(loginRedirect)
	if err != nil {
		log.Printf("LOGIN_REDIRECT_URL is not a valid URL, %v", loginRedirect)
		return &url.URL{}
	}
	return loginRedirectURL
}

func getLogoutRedirectURL(r *http.Request) *url.URL {
	logoutRedirect := r.Header.Get("X-Okta-Nginx-Logout-Redirect-Url")
	logoutRedirectURL := & url.URL{}
	if logoutRedirect != "" {
		var err error
		logoutRedirectURL, err = url.Parse(logoutRedirect)
		if err != nil {
			log.Printf("LOGOUT_REDIRECT_URL is not a valid URL, %v", logoutRedirect)
			logoutRedirectURL = &url.URL{}
		}
	}
	if (logoutRedirectURL.Scheme == "" || logoutRedirectURL.Host == ""){
		requestOriginURL := getRequestOriginURL(r)
		logoutRedirectURL.Scheme = requestOriginURL.Scheme
		logoutRedirectURL.Host = requestOriginURL.Host
	}
	return logoutRedirectURL
}

func getTemplate(templateText string) (*template.Template, error) {
	templateCacheMu.Lock()
	defer templateCacheMu.Unlock()
	t, ok := templateCache[templateText]
	if ok {
		return t, nil
	}
	t, err := template.New("").Funcs(sprig.TxtFuncMap()).Parse(templateText)
	if err != nil {
		return nil, err
	}
	return t, nil
}
