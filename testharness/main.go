// Minimal local OIDC AS + mock MCP resource with Dynamic Client Registration
// For development/testing only. Not production-ready.
package main

import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "log"
    "math/big"
    "net/http"
    urlpkg "net/url"
    "strings"
    "sync"
    "time"
)

// tiny wrapper to parse URL without import name conflicts
func __import_url(raw string) (*urlpkg.URL, error) { return urlpkg.Parse(raw) }

// Helpers
func b64url(b []byte) string { return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=") }

// JWT helpers (manual RS256)
func signJWTRS256(header, payload map[string]any, priv *rsa.PrivateKey) (string, error) {
    h, _ := json.Marshal(header)
    p, _ := json.Marshal(payload)
    hp := b64url(h) + "." + b64url(p)
    sum := sha256.Sum256([]byte(hp))
    sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
    if err != nil {
        return "", err
    }
    return hp + "." + b64url(sig), nil
}

func verifyJWTRS256(token string, pub *rsa.PublicKey) (map[string]any, error) {
    parts := strings.Split(token, ".")
    if len(parts) != 3 { return nil, http.ErrNoCookie }
    hp := parts[0] + "." + parts[1]
    sig, err := base64.RawURLEncoding.DecodeString(parts[2])
    if err != nil { return nil, err }
    sum := sha256.Sum256([]byte(hp))
    if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil { return nil, err }
    payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil { return nil, err }
    var claims map[string]any
    if err := json.Unmarshal(payloadBytes, &claims); err != nil { return nil, err }
    return claims, nil
}

// State
var (
    privKey *rsa.PrivateKey
    pubKey  *rsa.PublicKey
    keyKid  string

    issuer = "http://127.0.0.1:8085"

    muClients sync.Mutex
    clients   = map[string][]string{} // client_id -> redirect_uris

    muCodes sync.Mutex
    codes   = map[string]struct{
        ClientID      string
        RedirectURI   string
        CodeChallenge string
        Resource      string
        IssuedAt      time.Time
    }{}
)

func newClientID() string {
    b := make([]byte, 16)
    _, _ = rand.Read(b)
    return b64url(b)
}

func newCode() string {
    b := make([]byte, 16)
    _, _ = rand.Read(b)
    return b64url(b)
}

func handleWellKnown(w http.ResponseWriter, r *http.Request) {
    meta := map[string]any{
        "issuer": issuer,
        "authorization_endpoint": issuer + "/authorize",
        "token_endpoint": issuer + "/token",
        "jwks_uri": issuer + "/jwks.json",
        "registration_endpoint": issuer + "/register",
        "scopes_supported": []string{"openid", "profile"},
        "response_types_supported": []string{"code"},
        "grant_types_supported": []string{"authorization_code"},
        "code_challenge_methods_supported": []string{"S256"},
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(meta)
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
    // Build simple RSA JWK
    n := b64url(pubKey.N.Bytes())
    e := b64url(big.NewInt(int64(pubKey.E)).Bytes())
    jwk := map[string]any{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": keyKid, "n": n, "e": e,
    }
    jwks := map[string]any{"keys": []any{jwk}}
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(jwks)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }
    var req struct {
        RedirectURIs []string `json:"redirect_uris"`
        ClientName   string   `json:"client_name"`
    }
    _ = json.NewDecoder(r.Body).Decode(&req)
    if len(req.RedirectURIs) == 0 {
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client_metadata"})
        return
    }
    id := newClientID()
    muClients.Lock()
    clients[id] = req.RedirectURIs
    muClients.Unlock()
    resp := map[string]any{
        "client_id": id,
        "token_endpoint_auth_method": "none",
        "redirect_uris": req.RedirectURIs,
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(resp)
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()
    clientID := q.Get("client_id")
    redirectURI := q.Get("redirect_uri")
    state := q.Get("state")
    challenge := q.Get("code_challenge")
    method := q.Get("code_challenge_method")
    resource := q.Get("resource")

    muClients.Lock()
    allowed, ok := clients[clientID]
    muClients.Unlock()
    if !ok {
        w.WriteHeader(http.StatusBadRequest)
        _, _ = w.Write([]byte("unknown client"))
        return
    }
    okRedirect := false
    for _, u := range allowed {
        if u == redirectURI { okRedirect = true; break }
    }
    if !okRedirect || method != "S256" || challenge == "" {
        w.WriteHeader(http.StatusBadRequest)
        _, _ = w.Write([]byte("invalid_request"))
        return
    }
    code := newCode()
    muCodes.Lock()
    codes[code] = struct{
        ClientID      string
        RedirectURI   string
        CodeChallenge string
        Resource      string
        IssuedAt      time.Time
    }{ClientID: clientID, RedirectURI: redirectURI, CodeChallenge: challenge, Resource: resource, IssuedAt: time.Now()}
    muCodes.Unlock()

    http.Redirect(w, r, redirectURI+"?code="+code+"&state="+state, http.StatusFound)
}

func pkceS256(verifier string) string {
    sum := sha256.Sum256([]byte(verifier))
    return b64url(sum[:])
}

func handleToken(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }
    if err := r.ParseForm(); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    grant := r.Form.Get("grant_type")
    code := r.Form.Get("code")
    redirectURI := r.Form.Get("redirect_uri")
    clientID := r.Form.Get("client_id")
    verifier := r.Form.Get("code_verifier")

    if grant != "authorization_code" {
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(map[string]any{"error": "unsupported_grant_type"})
        return
    }

    muCodes.Lock()
    c, ok := codes[code]
    if ok { delete(codes, code) }
    muCodes.Unlock()
    if !ok {
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
        return
    }
    if c.ClientID != clientID || c.RedirectURI != redirectURI || c.CodeChallenge != pkceS256(verifier) {
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
        return
    }

    now := time.Now().Unix()
    exp := time.Now().Add(5 * time.Minute).Unix()
    aud := []string{}
    if c.Resource != "" { aud = []string{c.Resource} }

    header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": keyKid}
    payload := map[string]any{
        "iss": issuer, "sub": "test-sub", "aud": aud, "iat": now, "exp": exp, "scope": "openid profile",
    }
    token, err := signJWTRS256(header, payload, privKey)
    if err != nil { w.WriteHeader(http.StatusInternalServerError); return }

    resp := map[string]any{
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 300,
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(resp)
}

func handleResource(w http.ResponseWriter, r *http.Request) {
    // Protected resource at root; require valid Bearer JWT
    auth := r.Header.Get("Authorization")
    if !strings.HasPrefix(auth, "Bearer ") {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    tok := strings.TrimPrefix(auth, "Bearer ")
    claims, err := verifyJWTRS256(tok, pubKey)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    // Basic exp check
    if exp, ok := claims["exp"].(float64); ok {
        if time.Now().Unix() > int64(exp) {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func isSafePath(p string) bool {
    if strings.Contains(p, "..") { return false }
    if strings.HasPrefix(p, "/tmp/") { return true }
    if strings.HasPrefix(strings.ToLower(p), "c:\\tmp\\") { return true }
    return false
}

func isPrivateHost(hostport string) bool {
    // Very naive checks sufficient for harness
    h := hostport
    if i := strings.LastIndex(h, ":"); i > 0 {
        if !strings.Contains(h, "]") { h = h[:i] }
    }
    l := strings.ToLower(strings.Trim(h, "[]"))
    if l == "localhost" || l == "::1" || strings.HasPrefix(l, "127.") || strings.HasPrefix(l, "10.") || strings.HasPrefix(l, "192.168.") || strings.HasPrefix(l, "169.254.") {
        return true
    }
    if strings.HasPrefix(l, "172.") {
        parts := strings.Split(l, ".")
        if len(parts) >= 2 {
            switch parts[1] {
            case "16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31":
                return true
            }
        }
    }
    return false
}

func handleTools(w http.ResponseWriter, r *http.Request) {
    // Public description; no auth required
    resp := map[string]any{
        "tools": []any{
            map[string]any{"name": "read_file", "description": "Reads a file under /tmp or C:\\tmp\\ only"},
            map[string]any{"name": "fetch_url", "description": "Fetches a URL with SSRF protections"},
        },
        "policy": map[string]any{
            "read_file": map[string]any{"roots": []string{"/tmp/", "C:\\tmp\\"}},
            "fetch_url": map[string]any{"blocked": []string{"localhost", "127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}},
        },
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(resp)
}

var (
    muRate        sync.Mutex
    rateWindowBeg time.Time
    rateCount     int
)

func handleToolRun(w http.ResponseWriter, r *http.Request) {
    // Enforce POST
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    // Simple global rate limit: >3 requests within 1s => 429 Retry-After: 1
    now := time.Now()
    muRate.Lock()
    if rateWindowBeg.IsZero() || now.Sub(rateWindowBeg) > time.Second {
        rateWindowBeg = now
        rateCount = 0
    }
    rateCount++
    over := rateCount > 3
    muRate.Unlock()
    if over {
        w.Header().Set("Retry-After", "1")
        w.WriteHeader(http.StatusTooManyRequests)
        _ = json.NewEncoder(w).Encode(map[string]any{"error": "rate_limited", "message": "too many requests"})
        return
    }

    // Require Bearer JWT
    auth := r.Header.Get("Authorization")
    if !strings.HasPrefix(auth, "Bearer ") {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    tok := strings.TrimPrefix(auth, "Bearer ")
    if _, err := verifyJWTRS256(tok, pubKey); err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    var req struct {
        Tool string                 `json:"tool"`
        Args map[string]any        `json:"args"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_request"})
        return
    }

    if req.Tool == "read_file" {
        pathVal, _ := req.Args["path"].(string)
        if !isSafePath(pathVal) {
            w.WriteHeader(http.StatusForbidden)
            _ = json.NewEncoder(w).Encode(map[string]any{"error": "policy_violation", "message": "path outside allowed root"})
            return
        }
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "tool": req.Tool, "path": pathVal})
        return
    }

    if req.Tool == "fetch_url" {
        raw, _ := req.Args["url"].(string)
        u, err := __import_url(raw)
        if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
            w.WriteHeader(http.StatusBadRequest)
            _ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_request", "message": "unsupported scheme"})
            return
        }
        if isPrivateHost(u.Host) {
            w.WriteHeader(http.StatusForbidden)
            _ = json.NewEncoder(w).Encode(map[string]any{"error": "ssrf_blocked", "message": "private address blocked"})
            return
        }
        client := &http.Client{ Timeout: 2 * time.Second }
        resp, err := client.Get(u.String())
        if err != nil {
            w.WriteHeader(http.StatusBadGateway)
            _ = json.NewEncoder(w).Encode(map[string]any{"error": "upstream_error", "message": err.Error()})
            return
        }
        defer resp.Body.Close()
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": resp.StatusCode})
        return
    }

    w.WriteHeader(http.StatusForbidden)
    _ = json.NewEncoder(w).Encode(map[string]any{"error": "policy_violation", "message": "tool not permitted"})
}

func main() {
    // Generate ephemeral RSA key
    k, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil { log.Fatal(err) }
    privKey = k
    pubKey = &k.PublicKey
    keyKid = newClientID()

    mux := http.NewServeMux()
    mux.HandleFunc("/.well-known/openid-configuration", handleWellKnown)
    mux.HandleFunc("/.well-known/oauth-authorization-server", handleWellKnown)
    mux.HandleFunc("/jwks.json", handleJWKS)
    mux.HandleFunc("/register", handleRegister)
    mux.HandleFunc("/authorize", handleAuthorize)
    mux.HandleFunc("/token", handleToken)
    mux.HandleFunc("/tools", handleTools)
    mux.HandleFunc("/tool/run", handleToolRun)
    mux.HandleFunc("/", handleResource)

    addr := ":8085"
    log.Printf("Test harness listening on %s (issuer %s)", addr, issuer)
    log.Fatal(http.ListenAndServe(addr, mux))
}
