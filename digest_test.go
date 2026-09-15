package digest

import (
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"golang.org/x/net/websocket"
)

func TestRandomHex(t *testing.T) {
	lengths := []int{0, 8, 16, 32}
	for _, l := range lengths {
		res := randomHex(l)
		if len(res) != l {
			t.Errorf("randomHex(%d) length = %d, want %d", l, len(res), l)
		}
		for _, c := range res {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("randomHex(%d) returned invalid hex char: %c", l, c)
			}
		}
	}

	// Multiple calls should generally not produce the same string for length >= 16
	h1 := randomHex(16)
	h2 := randomHex(16)
	if h1 == h2 {
		t.Errorf("randomHex(16) generated identical values: %s", h1)
	}
}

func TestParseAuthParam(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "quoted realm",
			input:    `realm="secret"`,
			expected: "secret",
		},
		{
			name:     "quoted nonce with whitespace",
			input:    ` nonce="12345abc"`,
			expected: "12345abc",
		},
		{
			name:     "unquoted qop",
			input:    `qop=auth`,
			expected: "auth",
		},
		{
			name:     "unquoted algorithm",
			input:    `algorithm=MD5`,
			expected: "MD5",
		},
		{
			name:     "empty quoted value",
			input:    `uri=""`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAuthParam(tt.input)
			if got != tt.expected {
				t.Errorf("parseAuthParam(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestComputeMD5Password(t *testing.T) {
	user := "tam"
	realm := "secret"
	pass := "test"

	expectedPlain := fmt.Sprintf("%s:%s:%s", user, realm, pass)
	expectedMD5 := fmt.Sprintf("%x", md5.Sum([]byte(expectedPlain)))

	got := ComputeMD5Password(user, realm, pass)
	if got != expectedMD5 {
		t.Errorf("ComputeMD5Password() = %s, want %s", got, expectedMD5)
	}
}

func TestComputeResponse(t *testing.T) {
	A1MD5 := ComputeMD5Password("user", "realm", "pass")
	method := "GET"
	uri := "/index.html"
	nonce := "123456"
	nc := "00000001"
	cnonce := "abcdef"

	A2 := method + ":" + uri
	A2MD5 := fmt.Sprintf("%x", md5.Sum([]byte(A2)))
	expectedResp := fmt.Sprintf("%x", md5.Sum([]byte(A1MD5+":"+nonce+":"+nc+":"+cnonce+":auth:"+A2MD5)))

	got := computeResponse(A1MD5, method, uri, nonce, nc, cnonce)
	if got != expectedResp {
		t.Errorf("computeResponse() = %s, want %s", got, expectedResp)
	}
}

func TestComputeAuth(t *testing.T) {
	t.Run("Digest scheme success", func(t *testing.T) {
		challenge := `Digest realm="my_realm", nonce="my_nonce", algorithm=MD5, qop="auth"`
		uri := "/protected"
		user := "alice"
		pass := "secret123"
		method := "GET"

		authHeader := ComputeAuth(challenge, uri, user, pass, method)
		if !strings.HasPrefix(authHeader, "Digest ") {
			t.Fatalf("ComputeAuth() header does not start with 'Digest ': %s", authHeader)
		}

		if !strings.Contains(authHeader, `username="alice"`) {
			t.Errorf("missing username in authHeader: %s", authHeader)
		}
		if !strings.Contains(authHeader, `realm="my_realm"`) {
			t.Errorf("missing realm in authHeader: %s", authHeader)
		}
		if !strings.Contains(authHeader, `nonce="my_nonce"`) {
			t.Errorf("missing nonce in authHeader: %s", authHeader)
		}
		if !strings.Contains(authHeader, `uri="/protected"`) {
			t.Errorf("missing uri in authHeader: %s", authHeader)
		}
		if !strings.Contains(authHeader, "algorithm=MD5") {
			t.Errorf("missing algorithm in authHeader: %s", authHeader)
		}
		if !strings.Contains(authHeader, "qop=auth") {
			t.Errorf("missing qop in authHeader: %s", authHeader)
		}
		if !strings.Contains(authHeader, "nc=00000001") {
			t.Errorf("missing nc in authHeader: %s", authHeader)
		}
		if !strings.Contains(authHeader, `cnonce="e79e26e0d17c978d"`) {
			t.Errorf("missing cnonce in authHeader: %s", authHeader)
		}
		if !strings.Contains(authHeader, `response="`) {
			t.Errorf("missing response in authHeader: %s", authHeader)
		}
	})

	t.Run("Basic scheme returns empty", func(t *testing.T) {
		challenge := `Basic realm="my_realm"`
		res := ComputeAuth(challenge, "/test", "u", "p", "GET")
		if res != "" {
			t.Errorf("ComputeAuth with Basic should return empty, got %q", res)
		}
	})

	t.Run("Unknown scheme returns empty", func(t *testing.T) {
		challenge := `Bearer token="abc"`
		res := ComputeAuth(challenge, "/test", "u", "p", "GET")
		if res != "" {
			t.Errorf("ComputeAuth with Bearer should return empty, got %q", res)
		}
	})
}

func TestCheckAuth(t *testing.T) {
	user := "tam"
	realm := "secret"
	pass := "test"
	uri := "/api"
	method := "GET"
	nonce := "random_nonce"

	challenge := fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=MD5, qop="auth"`, realm, nonce)
	validAuthHeader := ComputeAuth(challenge, uri, user, pass, method)

	mockCheckHandler := func(u, r string) string {
		if u == user && r == realm {
			return ComputeMD5Password(u, r, pass)
		}
		return ""
	}

	t.Run("valid auth", func(t *testing.T) {
		if !CheckAuth(validAuthHeader, method, mockCheckHandler) {
			t.Error("CheckAuth failed for valid authorization header")
		}
	})

	t.Run("empty auth header", func(t *testing.T) {
		if CheckAuth("", method, mockCheckHandler) {
			t.Error("CheckAuth should fail for empty header")
		}
	})

	t.Run("non-Digest header", func(t *testing.T) {
		if CheckAuth("Basic dXNlcjpwYXNz", method, mockCheckHandler) {
			t.Error("CheckAuth should fail for non-Digest header")
		}
	})

	t.Run("wrong method", func(t *testing.T) {
		if CheckAuth(validAuthHeader, "POST", mockCheckHandler) {
			t.Error("CheckAuth should fail when HTTP method doesn't match")
		}
	})

	t.Run("wrong password (checkHandler returns empty)", func(t *testing.T) {
		wrongHandler := func(u, r string) string { return "" }
		if CheckAuth(validAuthHeader, method, wrongHandler) {
			t.Error("CheckAuth should fail if checkHandler returns empty")
		}
	})

	t.Run("invalid qop", func(t *testing.T) {
		invalidQopHeader := strings.Replace(validAuthHeader, "qop=auth", "qop=auth-int", 1)
		if CheckAuth(invalidQopHeader, method, mockCheckHandler) {
			t.Error("CheckAuth should fail for non-auth qop")
		}
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		invalidAlgoHeader := strings.Replace(validAuthHeader, "algorithm=MD5", "algorithm=SHA256", 1)
		if CheckAuth(invalidAlgoHeader, method, mockCheckHandler) {
			t.Error("CheckAuth should fail for non-MD5 algorithm")
		}
	})

	t.Run("tampered response hash", func(t *testing.T) {
		tamperedHeader := strings.Replace(validAuthHeader, `response="`, `response="bad`, 1)
		if CheckAuth(tamperedHeader, method, mockCheckHandler) {
			t.Error("CheckAuth should fail for tampered response")
		}
	})
}

func TestGetUsername(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		expected   string
	}{
		{
			name:       "valid digest header with username",
			authHeader: `Digest username="alice", realm="test"`,
			expected:   "alice",
		},
		{
			name:       "empty header",
			authHeader: "",
			expected:   "",
		},
		{
			name:       "basic auth header",
			authHeader: "Basic dXNlcjpwYXNz",
			expected:   "",
		},
		{
			name:       "digest header without username",
			authHeader: `Digest realm="test", nonce="123"`,
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			got := GetUsername(req)
			if got != tt.expected {
				t.Errorf("GetUsername() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestStrictHandlerAndHandler(t *testing.T) {
	checkPassword := func(user string) string {
		if user == "tam" {
			return "test"
		}
		return ""
	}

	nextHandlerCalled := false
	nextHandler := func(w http.ResponseWriter, r *http.Request) {
		nextHandlerCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Authorized!"))
	}

	handler := Handler(checkPassword, nextHandler)

	t.Run("unauthorized request returns 401 with WWW-Authenticate", func(t *testing.T) {
		nextHandlerCalled = false
		req := httptest.NewRequest("GET", "/secret", nil)
		rec := httptest.NewRecorder()

		handler(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		wwwAuth := rec.Header().Get("WWW-Authenticate")
		if !strings.HasPrefix(wwwAuth, "Digest realm=\"secret\", nonce=\"") {
			t.Errorf("WWW-Authenticate header invalid: %s", wwwAuth)
		}
		if nextHandlerCalled {
			t.Error("nextHandler should not be called on unauthorized request")
		}
	})

	t.Run("authorized request succeeds", func(t *testing.T) {
		nextHandlerCalled = false
		// First get the challenge nonce
		initReq := httptest.NewRequest("GET", "/secret", nil)
		initRec := httptest.NewRecorder()
		handler(initRec, initReq)

		wwwAuth := initRec.Header().Get("WWW-Authenticate")
		authHeader := ComputeAuth(wwwAuth, "/secret", "tam", "test", "GET")

		req := httptest.NewRequest("GET", "/secret", nil)
		req.Header.Set("Authorization", authHeader)
		rec := httptest.NewRecorder()

		handler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if !nextHandlerCalled {
			t.Error("nextHandler was not called")
		}
		if rec.Body.String() != "Authorized!" {
			t.Errorf("body = %q, want %q", rec.Body.String(), "Authorized!")
		}
	})
}

func TestCheckPasswordAndCreateA1MD5AndLogger(t *testing.T) {
	if CheckPassword("tam") != "test" {
		t.Errorf("CheckPassword('tam') != 'test'")
	}
	if CheckPassword("unknown") != "" {
		t.Errorf("CheckPassword('unknown') != ''")
	}

	a1 := CreateA1MD5("tam", "secret")
	expected := ComputeMD5Password("tam", "secret", "test")
	if a1 != expected {
		t.Errorf("CreateA1MD5('tam', 'secret') = %s, want %s", a1, expected)
	}
	if CreateA1MD5("other", "secret") != "" {
		t.Errorf("CreateA1MD5('other', 'secret') != ''")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	Logger(rec, req)
	if rec.Body.String() != "Hello." {
		t.Errorf("Logger body = %q, want 'Hello.'", rec.Body.String())
	}
}

func TestStrictEchoHandler(t *testing.T) {
	e := echo.New()

	checkHandler := func(u, r string) string {
		if u == "tam" && r == "secret" {
			return ComputeMD5Password("tam", "secret", "test")
		}
		return ""
	}

	echoHandlerCalled := false
	echoHandler := func(c echo.Context) error {
		echoHandlerCalled = true
		return c.String(http.StatusOK, "Echo OK")
	}

	wrapped := StrictEchoHandler(checkHandler, echoHandler)

	t.Run("unauthorized request", func(t *testing.T) {
		echoHandlerCalled = false
		req := httptest.NewRequest(http.MethodGet, "/echo", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := wrapped(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Digest realm=\"secret\"") {
			t.Errorf("invalid WWW-Authenticate: %s", rec.Header().Get("WWW-Authenticate"))
		}
		if echoHandlerCalled {
			t.Error("echoHandler should not have been called")
		}
	})

	t.Run("authorized request", func(t *testing.T) {
		echoHandlerCalled = false
		// 1. Get nonce
		req1 := httptest.NewRequest(http.MethodGet, "/echo", nil)
		rec1 := httptest.NewRecorder()
		c1 := e.NewContext(req1, rec1)
		_ = wrapped(c1)

		wwwAuth := rec1.Header().Get("WWW-Authenticate")
		auth := ComputeAuth(wwwAuth, "/echo", "tam", "test", "GET")

		// 2. Request with auth header
		req2 := httptest.NewRequest(http.MethodGet, "/echo", nil)
		req2.Header.Set("Authorization", auth)
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)

		err := wrapped(c2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rec2.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec2.Code, http.StatusOK)
		}
		if !echoHandlerCalled {
			t.Error("echoHandler should have been called")
		}
	})
}

func TestDigestAuthClient(t *testing.T) {
	user := "tam"
	pass := "test"

	server := httptest.NewServer(http.HandlerFunc(Handler(CheckPassword, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("POST received: " + string(body)))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("GET success"))
	})))
	defer server.Close()

	t.Run("Get success with correct credentials", func(t *testing.T) {
		client := NewDigestAuthClient(server.Client(), user, pass)
		resp, err := client.Get(server.URL + "/protected")
		if err != nil {
			t.Fatalf("client.Get failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "GET success" {
			t.Errorf("body = %q, want 'GET success'", string(body))
		}
	})

	t.Run("Get failure with wrong credentials", func(t *testing.T) {
		client := NewDigestAuthClient(server.Client(), user, "wrong_pass")
		resp, err := client.Get(server.URL + "/protected")
		if err != nil {
			t.Fatalf("client.Get failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("Do on protected endpoint", func(t *testing.T) {
		client := NewDigestAuthClient(server.Client(), user, pass)
		req, _ := http.NewRequest("GET", server.URL+"/protected", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("client.Do failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("Do on unprotected endpoint", func(t *testing.T) {
		openServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("open"))
		}))
		defer openServer.Close()

		client := NewDigestAuthClient(openServer.Client(), user, pass)
		req, _ := http.NewRequest("GET", openServer.URL+"/open", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("client.Do failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "open" {
			t.Errorf("body = %q, want 'open'", string(body))
		}
	})

	t.Run("PostForm success", func(t *testing.T) {
		client := NewDigestAuthClient(server.Client(), user, pass)
		formData := url.Values{"key": {"value123"}}
		resp, err := client.PostForm(server.URL+"/protected", formData)
		if err != nil {
			t.Fatalf("client.PostForm failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})
}

func TestDialWebSocket(t *testing.T) {
	user := "tam"
	pass := "test"

	wsHandler := websocket.Handler(func(ws *websocket.Conn) {
		var msg string
		err := websocket.Message.Receive(ws, &msg)
		if err != nil {
			return
		}
		_ = websocket.Message.Send(ws, "echo:"+msg)
	})

	// Server handling both HTTP 401 challenge and WebSocket upgrade
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !CheckAuth(auth, r.Method, func(u, realm string) string {
			if u == user {
				return ComputeMD5Password(u, realm, pass)
			}
			return ""
		}) {
			nonce := randomHex(32)
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="secret", nonce="%s", algorithm=MD5, qop=auth`, nonce))
			http.Error(w, "Auth required", http.StatusUnauthorized)
			return
		}

		wsHandler.ServeHTTP(w, r)
	}))
	defer server.Close()

	// Convert server URL from http://... to ws://...
	wsURL := "ws://" + server.URL[len("http://"):] + "/ws"

	t.Run("successful websocket connection with digest auth", func(t *testing.T) {
		ws, err := DialWebSocket(wsURL, "http://localhost", user, pass)
		if err != nil {
			t.Fatalf("DialWebSocket failed: %v", err)
		}
		defer ws.Close()

		sendMsg := "hello-websocket"
		if err := websocket.Message.Send(ws, sendMsg); err != nil {
			t.Fatalf("websocket send failed: %v", err)
		}

		var recvMsg string
		if err := websocket.Message.Receive(ws, &recvMsg); err != nil {
			t.Fatalf("websocket receive failed: %v", err)
		}

		if recvMsg != "echo:"+sendMsg {
			t.Errorf("received = %q, want %q", recvMsg, "echo:"+sendMsg)
		}
	})

	t.Run("websocket connection failure with wrong password", func(t *testing.T) {
		_, err := DialWebSocket(wsURL, "http://localhost", user, "wrongpass")
		if err == nil {
			t.Error("DialWebSocket should fail with wrong credentials")
		}
	})

	t.Run("websocket connection failure with invalid url", func(t *testing.T) {
		_, err := DialWebSocket("ws://invalid.local.domain:99999/ws", "http://localhost", user, pass)
		if err == nil {
			t.Error("DialWebSocket should fail with invalid host")
		}
	})
}
