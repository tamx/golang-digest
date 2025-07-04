package digest

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/websocket"
)

func randomHex(precision int) string {
	result := ""
	for range precision {
		random := rand.Intn(16)
		result += fmt.Sprintf("%x", random)
	}
	return result
}

func ComputeAuth(authenticate string, uri string,
	username string, password string,
	method string) string {
	if strings.HasPrefix(authenticate, "Basic ") {
		// not implemented
	} else if strings.HasPrefix(authenticate, "Digest ") {
		authparam := strings.Split(authenticate[7:], ",")
		realm := ""
		nonce := ""
		for s := range authparam {
			if strings.Contains(authparam[s], "realm=") {
				realm = parseAuthParam(authparam[s])
			}
			if strings.Contains(authparam[s], "nonce=") {
				nonce = parseAuthParam(authparam[s])
			}
		}
		nc := "00000001"
		cnonce := "e79e26e0d17c978d"
		A1MD5 := ComputeMD5Password(username, realm,
			password)
		responseMD5 := computeResponse(A1MD5,
			method, uri, nonce, nc, cnonce)

		resheader := "Digest username=\"" + username + "\", realm=\""
		resheader += realm + "\", nonce=\"" + nonce + "\", uri=\"" + uri
		resheader += "\", algorithm=MD5, qop=auth, nc=" + nc
		resheader += ", cnonce=\"" + cnonce + "\", response=\""
		resheader += responseMD5 + "\""

		return resheader
	}
	return ""
}

func parseAuthParam(param string) string {
	param = param[strings.Index(param, "=")+1:]
	if strings.Contains(param, "\"") {
		param = param[strings.Index(param, "\"")+1:]
		param = param[:strings.Index(param, "\"")]
	}
	return param
}

func ComputeMD5Password(username,
	realm, password string) string {
	A1 := username + ":" + realm + ":" + password
	A1MD5 := fmt.Sprintf("%x", md5.Sum([]byte(A1)))
	return A1MD5
}

func computeResponse(A1MD5,
	method, uri, nonce, nc, cnonce string) string {
	A2 := method + ":" + uri
	A2MD5 := fmt.Sprintf("%x", md5.Sum([]byte(A2)))
	response := A1MD5 + ":" + nonce + ":" + nc + ":" + cnonce
	response += ":auth:" + A2MD5
	responseMD5 := fmt.Sprintf("%x", md5.Sum([]byte(response)))
	return responseMD5
}

func CheckAuth(authenticate string, method string,
	checkHandler func(string, string) string) bool {
	if authenticate == "" {
		return false
	}
	if !strings.HasPrefix(authenticate, "Digest ") {
		return false
	}
	authparam := strings.Split(authenticate[7:], ",")
	username := ""
	realm := ""
	nonce := ""
	uri := ""
	nc := ""
	cnonce := ""
	response := ""
	for s := range authparam {
		if strings.Contains(authparam[s], "username=") {
			username = parseAuthParam(authparam[s])
		}
		if strings.Contains(authparam[s], "realm=") {
			realm = parseAuthParam(authparam[s])
		}
		if strings.Contains(authparam[s], " nonce=") {
			nonce = parseAuthParam(authparam[s])
		}
		if strings.Contains(authparam[s], "uri=") {
			uri = parseAuthParam(authparam[s])
		}
		if strings.Contains(authparam[s], "nc=") {
			nc = parseAuthParam(authparam[s])
		}
		if strings.Contains(authparam[s], "cnonce=") {
			cnonce = parseAuthParam(authparam[s])
		}
		if strings.Contains(authparam[s], "response=") {
			response = parseAuthParam(authparam[s])
		}
		if strings.Contains(authparam[s], "qop=") {
			if parseAuthParam(authparam[s]) != "auth" {
				return false
			}
		}
		if strings.Contains(authparam[s], "algorithm=") {
			if parseAuthParam(authparam[s]) != "MD5" {
				return false
			}
		}
	}

	A1MD5 := checkHandler(username, realm)
	if A1MD5 == "" {
		return false
	}
	expected := computeResponse(A1MD5,
		method, uri, nonce, nc, cnonce)
	return expected == response
}

func GetUsername(r *http.Request) string {
	authenticate := r.Header.Get("Authorization")
	if authenticate == "" {
		return ""
	}
	if !strings.HasPrefix(authenticate, "Digest ") {
		return ""
	}
	authparam := strings.Split(authenticate[7:], ",")
	username := ""
	for s := range authparam {
		if strings.Contains(authparam[s], "username=") {
			username = parseAuthParam(authparam[s])
			return username
		}
	}
	return ""
}

func StrictHandler(checkHandler func(string, string) string,
	handler func(http.ResponseWriter, *http.Request)) func(w http.ResponseWriter,
	r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		method := r.Method
		auth := r.Header.Get("Authorization")
		if CheckAuth(auth, method, checkHandler) {
			handler(w, r)
		} else {
			nonce := randomHex(32)
			w.Header().Set("WWW-Authenticate",
				"Digest realm=\"secret\", nonce=\""+nonce+
					"\", algorithm=MD5, qop=auth")
			http.Error(w, "Auth required", http.StatusUnauthorized)
		}
	}
}

func Handler(checkPassword func(string) string,
	handler func(http.ResponseWriter, *http.Request)) func(w http.ResponseWriter,
	r *http.Request) {
	checkHandler := func(username, realm string) string {
		password := checkPassword(username)
		A1MD5 := ComputeMD5Password(username,
			realm, password)
		return A1MD5
	}
	return StrictHandler(checkHandler, handler)
}

func CheckPassword(username string) string {
	if username == "tam" {
		return "test"
	}
	return ""
}

func CreateA1MD5(username, realm string) string {
	if username == "tam" {
		A1MD5 := ComputeMD5Password(
			username, realm,
			"test")
		return A1MD5
	}
	return ""
}

func Logger(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello.")
}

type DigestAuthClient struct {
	client   *http.Client
	username string
	password string
}

func NewDigestAuthClient(c *http.Client, user, pass string) *DigestAuthClient {
	client := new(DigestAuthClient)
	client.client = c
	client.username = user
	client.password = pass
	return client
}

func (c *DigestAuthClient) Get(url string) (resp *http.Response, err error) {
	resp, err = c.client.Get(url)
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		method := "GET"
		auth := resp.Header.Get("WWW-Authenticate")
		response := ComputeAuth(auth, url, c.username, c.password, method)
		req, _ := http.NewRequest(method, url, nil)
		req.Header.Set("Authorization", response)
		resp, err = c.client.Do(req)
	}
	return resp, err
}

func (c *DigestAuthClient) Do(req *http.Request) (resp *http.Response,
	err error) {
	resp, err = c.client.Get(req.URL.String())
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		method := req.Method
		auth := resp.Header.Get("WWW-Authenticate")
		response := ComputeAuth(auth, req.URL.String(),
			c.username, c.password, method)
		req.Header.Set("Authorization", response)
		resp, err = c.client.Do(req)
	} else if err == nil {
		resp, err = c.client.Do(req)
	}
	return resp, err
}

func (c *DigestAuthClient) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	resp, err = c.client.PostForm(url, data)
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		method := "POST"
		auth := resp.Header.Get("WWW-Authenticate")
		response := ComputeAuth(auth, url, c.username, c.password, method)
		req, _ := http.NewRequest(method, url, bytes.NewBufferString(data.Encode()))
		req.Header.Set("Authorization", response)
		resp, err = c.client.Do(req)
	}
	return resp, err
}

func DialWebSocket(url, origin string,
	user, pass string) (ws *websocket.Conn, err error) {
	resp, err := new(http.Client).Get("http:" + string(url[3:]))
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		method := "GET"
		auth := resp.Header.Get("WWW-Authenticate")
		response := ComputeAuth(auth, url, user, pass, method)
		config, err := websocket.NewConfig(url, origin)
		if err != nil {
			// log.Fatal(err)
			return nil, err
		}
		config.Header = http.Header{
			"Authorization": {response},
		}
		ws, err = websocket.DialConfig(config)
		return ws, err
	}
	return ws, err
}

func testServer() {
	http.HandleFunc("/", Handler(CheckPassword, Logger))
	http.ListenAndServe("0.0.0.0:8080", nil)
}

func testClient() {
	client := NewDigestAuthClient(new(http.Client), "tam", "test")
	resp, _ := client.Get("http://www.google.co.jp/")
	byteArray, _ := io.ReadAll(resp.Body)
	fmt.Println(string(byteArray))
}

func main() {
	testServer()
}
