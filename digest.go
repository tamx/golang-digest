package digest

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"strings"
)

func auth(authenticate string, uri string, username string, password string, method string) string {
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

var handler func(http.ResponseWriter, *http.Request) = nil
var checkHandler func(string) string = nil

func HandleFunc(pattern string, c func(string) string, h func(http.ResponseWriter, *http.Request)) {
	checkHandler = c
	handler = h
}

func CheckAuth(w http.ResponseWriter, r *http.Request) {
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

func CheckPassword(username string) string {
	if username == "tam" {
		return "test"
	}
	return ""
}

func Logger(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello.")
}

func main() {
	HandleFunc("/", CheckPassword, Logger)
	http.HandleFunc("/", CheckAuth)
	http.ListenAndServe(":8080", nil)
}
