package main

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func computeAuth(authenticate string, uri string, username string, password string, method string) string {
	if strings.HasPrefix(authenticate, "Basic ") {
		// not implemented
	} else if strings.HasPrefix(authenticate, "Digest ") {
		authparam := strings.Split(authenticate[7:], ",")
		realm := ""
		nonce := ""
		for s := range authparam {
			if strings.Index(authparam[s], "realm=") != -1 {
				realm = parseAuthParam(authparam[s])
			}
			if strings.Index(authparam[s], "nonce=") != -1 {
				nonce = parseAuthParam(authparam[s])
			}
		}
		nc := "00000001"
		cnonce := "e79e26e0d17c978d"
		responseMD5 := computeResponse(username, realm, password, method, uri, nonce, nc, cnonce)

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
	if strings.Index(param, "\"") != -1 {
		param = param[strings.Index(param, "\"")+1:]
		param = param[:strings.Index(param, "\"")]
	}
	return param
}

func computeResponse(username, realm, password, method, uri, nonce, nc, cnonce string) string {
	A1 := username + ":" + realm + ":" + password
	A1MD5 := fmt.Sprintf("%x", md5.Sum([]byte(A1)))
	A2 := method + ":" + uri
	A2MD5 := fmt.Sprintf("%x", md5.Sum([]byte(A2)))
	response := A1MD5 + ":" + nonce + ":" + nc + ":" + cnonce
	response += ":auth:" + A2MD5
	responseMD5 := fmt.Sprintf("%x", md5.Sum([]byte(response)))
	return responseMD5
}

func checkAuth(authenticate string, method string, checkHandler func(string) string) bool {
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
		if strings.Index(authparam[s], "username=") != -1 {
			username = parseAuthParam(authparam[s])
		}
		if strings.Index(authparam[s], "realm=") != -1 {
			realm = parseAuthParam(authparam[s])
		}
		if strings.Index(authparam[s], " nonce=") != -1 {
			nonce = parseAuthParam(authparam[s])
		}
		if strings.Index(authparam[s], "uri=") != -1 {
			uri = parseAuthParam(authparam[s])
		}
		if strings.Index(authparam[s], "nc=") != -1 {
			nc = parseAuthParam(authparam[s])
		}
		if strings.Index(authparam[s], "cnonce=") != -1 {
			cnonce = parseAuthParam(authparam[s])
		}
		if strings.Index(authparam[s], "response=") != -1 {
			response = parseAuthParam(authparam[s])
		}
		if strings.Index(authparam[s], "qop=") != -1 {
			if parseAuthParam(authparam[s]) != "auth" {
				return false
			}
		}
		if strings.Index(authparam[s], "algorithm=") != -1 {
			if parseAuthParam(authparam[s]) != "MD5" {
				return false
			}
		}
	}

	password := checkHandler(username)
	if password == "" {
		return false
	}
	expected := computeResponse(username, realm, password,
		method, uri, nonce, nc, cnonce)
	if expected == response {
		return true
	}
	return false
}

func HandleFunc(checkHandler func(string) string, handler func(http.ResponseWriter, *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		method := r.Method
		auth := r.Header.Get("Authorization")
		if checkAuth(auth, method, checkHandler) {
			handler(w, r)
		} else {
			w.Header().Set("WWW-Authenticate",
				"Digest realm=\"secret\", nonce=\"12345678901234567890123456789012\", algorithm=MD5, qop=auth")
			http.Error(w, "Auth required", http.StatusUnauthorized)
		}
	}
}

func CheckPassword(username string) string {
	if username == "tam" {
		return "test"
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
		response := computeAuth(auth, url, c.username, c.password, method)
		req, _ := http.NewRequest(method, url, nil)
		req.Header.Set("Authorization", response)
		resp, err = c.client.Do(req)
	}
	return resp, err
}

func (c *DigestAuthClient) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	resp, err = c.client.PostForm(url, data)
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		method := "POST"
		auth := resp.Header.Get("WWW-Authenticate")
		response := computeAuth(auth, url, c.username, c.password, method)
		req, _ := http.NewRequest(method, url, bytes.NewBufferString(data.Encode()))
		req.Header.Set("Authorization", response)
		resp, err = c.client.Do(req)
	}
	return resp, err
}

func testServer() {
	http.HandleFunc("/", HandleFunc(CheckPassword, Logger))
	http.ListenAndServe("0.0.0.0:8080", nil)
}

func testClient() {
	client := NewDigestAuthClient(new(http.Client), "tam", "test")
	resp, _ := client.Get("http://www.google.co.jp/")
	byteArray, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(byteArray))
}
