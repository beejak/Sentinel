// Vulnerable MCP-like server for testing probes. DO NOT USE IN PRODUCTION.
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
    "os"
    "strings"
    "sync"
    "time"
)

func parseURL(raw string) (*urlpkg.URL, error) { return urlpkg.Parse(raw) }

func b64url(b []byte) string { return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=") }

// JWT sign/verify (RS256)
func signJWTRS256(header, payload map[string]any, priv *rsa.PrivateKey) (string, error) {
    h, _ := json.Marshal(header)
    p, _ := json.Marshal(payload)
    hp := b64url(h) + "." + b64url(p)
    sum := sha256.Sum256([]byte(hp))
    sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
    if err != nil { return "", err }
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

var (
    privKey *rsa.PrivateKey
    pubKey  *rsa.PublicKey
    keyKid  string

    // Configurable vulnerabilities via env vars (default: vulnerable)
    allowGETPUT         = envBool("VULN_ALLOW_GET_PUT", true)
    allowTRACE          = envBool("VULN_ALLOW_TRACE", true)
    acceptMissingCT     = envBool("VULN_ACCEPT_MISSING_CT", true)
    allowTraversalPaths = envBool("VULN_ALLOW_TRAVERSAL", true)
    permissiveToolRun   = envBool("VULN_PERMISSIVE_TOOL_RUN", true)
    replayCodes         = envBool("VULN_REPLAY_CODE", true)
    acceptBogusToken    = envBool("VULN_ACCEPT_BOGUS_TOKEN", true)
    ssrfBlock           = envBool("VULN_SSRF_BLOCK", false) // default: vulnerable (no block)

    // New vuln flags
    acceptAlgNone       = envBool("VULN_ACCEPT_ALG_NONE", true)
    weakRSA             = envBool("VULN_WEAK_RSA_KEY", false)
    noHSTS              = envBool("VULN_NO_HSTS", true)
    dangerousTool       = envBool("VULN_DANGEROUS_TOOL", true)

    issuer = "http://127.0.0.1:8090"

    muClients sync.Mutex
    clients   = map[string][]string{}

    muCodes sync.Mutex
    codes   = map[string]struct{
        ClientID      string
        RedirectURI   string
        CodeChallenge string
        Resource      string
        IssuedAt      time.Time
    }{}
)

func envBool(name string, def bool) bool {
    v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
    if v == "" { return def }
    return v == "1" || v == "true" || v == "yes"
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
    n := b64url(pubKey.N.Bytes())
    e := b64url(big.NewInt(int64(pubKey.E)).Bytes())
    jwk := map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": keyKid, "n": n, "e": e}
    jwks := map[string]any{"keys": []any{jwk}}
    w.Header().Set("Content-Type", "application/json")
    if !noHSTS { w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains") }
    _ = json.NewEncoder(w).Encode(jwks)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }
    var req struct { RedirectURIs []string `json:"redirect_uris"` }
    _ = json.NewDecoder(r.Body).Decode(&req)
    if len(req.RedirectURIs) == 0 {
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client_metadata"})
        return
    }
    id := b64url([]byte(time.Now().Format(time.RFC3339Nano)))
    muClients.Lock()
    clients[id] = req.RedirectURIs
    muClients.Unlock()
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"client_id": id, "token_endpoint_auth_method": "none", "redirect_uris": req.RedirectURIs})
}

func pkceS256(verifier string) string {
    sum := sha256.Sum256([]byte(verifier))
    return b64url(sum[:])
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()
    clientID := q.Get("client_id")
    redirectURI := q.Get("redirect_uri")
    state := q.Get("state")
    challenge := q.Get("code_challenge")
    method := q.Get("code_challenge_method")
    resource := q.Get("resource")

    muClients.Lock(); allowed, ok := clients[clientID]; muClients.Unlock()
    if !ok {
        w.WriteHeader(http.StatusBadRequest); _, _ = w.Write([]byte("unknown client")); return
    }
    okRedirect := false
    for _, u := range allowed { if u == redirectURI { okRedirect = true; break } }
    if !okRedirect || method != "S256" || challenge == "" {
        w.WriteHeader(http.StatusBadRequest); _, _ = w.Write([]byte("invalid_request")); return
    }
    code := b64url([]byte(time.Now().Format(time.RFC3339Nano)))
    muCodes.Lock()
    codes[code] = struct{ ClientID, RedirectURI, CodeChallenge, Resource string; IssuedAt time.Time }{clientID, redirectURI, challenge, resource, time.Now()}
    muCodes.Unlock()

    http.Redirect(w, r, redirectURI+"?code="+code+"&state="+state, http.StatusFound)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost { w.WriteHeader(http.StatusMethodNotAllowed); return }
    if err := r.ParseForm(); err != nil { w.WriteHeader(http.StatusBadRequest); return }
    code := r.Form.Get("code")
    clientID := r.Form.Get("client_id")
    redirectURI := r.Form.Get("redirect_uri")
    verifier := r.Form.Get("code_verifier")

    muCodes.Lock()
    c, ok := codes[code]
    if ok && !replayCodes { delete(codes, code) } // secure server would always delete; vuln keeps if replayCodes
    muCodes.Unlock()
    if !ok { w.WriteHeader(http.StatusBadRequest); _ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"}); return }
    if c.ClientID != clientID || c.RedirectURI != redirectURI || c.CodeChallenge != pkceS256(verifier) {
        w.WriteHeader(http.StatusBadRequest); _ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"}); return
    }

    now, exp := time.Now().Unix(), time.Now().Add(10*time.Minute).Unix()
    header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": keyKid}
    aud := []string{}
    if c.Resource != "" { aud = []string{c.Resource} }
    payload := map[string]any{"iss": issuer, "sub": "vuln-sub", "aud": aud, "iat": now, "exp": exp, "scope": "openid profile"}
    token, err := signJWTRS256(header, payload, privKey)
    if err != nil { w.WriteHeader(http.StatusInternalServerError); return }
    _ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 600})
}

func pathAllowed(p string) bool {
    if permissiveToolRun { return true }
    if allowTraversalPaths { return true }
    if strings.Contains(p, "..") { return false }
    if strings.HasPrefix(p, "/tmp/") { return true }
    if strings.HasPrefix(strings.ToLower(p), "c:\\tmp\\") { return true }
    return false
}

func handleTools(w http.ResponseWriter, r *http.Request) {
    tools := []any{
        map[string]any{"name": "read_file", "description": "Reads files"},
        map[string]any{"name": "fetch_url", "description": "Fetches a URL (vulnerable by default)"},
    }
    if dangerousTool {
        tools = append(tools, map[string]any{"name": "exec", "description": "Executes system commands (dangerous)"})
    }
    w.Header().Set("Content-Type", "application/json")
    if !noHSTS { w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains") }
    _ = json.NewEncoder(w).Encode(map[string]any{
        "tools": tools,
        "policy": map[string]any{
            "read_file": map[string]any{"roots": []string{"/tmp/", "C\\tmp\\"}},
            "fetch_url": map[string]any{"note": "SSRF blocking disabled by default; set VULN_SSRF_BLOCK=true to enable basic checks"},
        },
    })
}

func handleToolRun(w http.ResponseWriter, r *http.Request) {
    // Methods
    if r.Method != http.MethodPost && !allowGETPUT {
        w.WriteHeader(http.StatusMethodNotAllowed); return
    }

    // TRACE allowed?
    if r.Method == http.MethodTrace && !allowTRACE {
        w.WriteHeader(http.StatusMethodNotAllowed); return
    }

    // Auth
    auth := r.Header.Get("Authorization")
    if !acceptBogusToken {
        if !strings.HasPrefix(auth, "Bearer ") { w.WriteHeader(http.StatusUnauthorized); _ = json.NewEncoder(w).Encode(map[string]any{"error":"unauthorized"}); return }
        tok := strings.TrimPrefix(auth, "Bearer ")
        // Accept alg=none if enabled
        if acceptAlgNone && strings.HasSuffix(tok, ".") {
            parts := strings.Split(tok, ".")
            if len(parts) == 3 && parts[2] == "" {
                // header check alg=none
                hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
                var hdr map[string]any; _ = json.Unmarshal(hb, &hdr)
                if v, ok := hdr["alg"].(string); ok && strings.EqualFold(v, "none") {
                    goto AUTH_OK
                }
            }
        }
        if _, err := verifyJWTRS256(tok, pubKey); err != nil { w.WriteHeader(http.StatusUnauthorized); _ = json.NewEncoder(w).Encode(map[string]any{"error":"unauthorized"}); return }
    }
AUTH_OK:

    // Content-Type enforcement
    ct := r.Header.Get("Content-Type")
    if ct == "" && !acceptMissingCT {
        w.WriteHeader(http.StatusBadRequest); _ = json.NewEncoder(w).Encode(map[string]any{"error":"invalid_request","message":"missing content-type"}); return
    }

    var req struct { Tool string `json:"tool"`; Args map[string]any `json:"args"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        if permissiveToolRun { w.WriteHeader(http.StatusOK); _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "note":"accepted invalid json"}); return }
        w.WriteHeader(http.StatusBadRequest); _ = json.NewEncoder(w).Encode(map[string]any{"error":"invalid_json"}); return
    }

    if req.Tool == "read_file" || permissiveToolRun {
        pathVal, _ := req.Args["path"].(string)
        if !permissiveToolRun && !pathAllowed(pathVal) {
            w.WriteHeader(http.StatusForbidden); _ = json.NewEncoder(w).Encode(map[string]any{"error":"policy_violation","message":"path outside allowed root"}); return
        }
        _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "tool": req.Tool, "path": pathVal}); return
    }

    if req.Tool == "fetch_url" {
        raw, _ := req.Args["url"].(string)
        u, err := parseURL(raw)
        if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
            w.WriteHeader(http.StatusBadRequest); _ = json.NewEncoder(w).Encode(map[string]any{"error":"invalid_request","message":"unsupported scheme"}); return
        }
        // Vulnerable by default: only block if VULN_SSRF_BLOCK=true
        if ssrfBlock {
            host := strings.ToLower(strings.Trim(u.Host, "[]"))
            if host == "localhost" || strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") || strings.HasPrefix(host, "169.254.") || host == "::1" {
                w.WriteHeader(http.StatusForbidden); _ = json.NewEncoder(w).Encode(map[string]any{"error":"ssrf_blocked"}); return
            }
            if strings.HasPrefix(host, "172.") {
                parts := strings.Split(host, ".")
                if len(parts) >= 2 {
                    switch parts[1] { case "16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31":
                        w.WriteHeader(http.StatusForbidden); _ = json.NewEncoder(w).Encode(map[string]any{"error":"ssrf_blocked"}); return }
                }
            }
        }
        client := &http.Client{ Timeout: 2 * time.Second }
        resp, err := client.Get(u.String())
        if err != nil { w.WriteHeader(http.StatusBadGateway); _ = json.NewEncoder(w).Encode(map[string]any{"error":"upstream_error"}); return }
        defer resp.Body.Close()
        _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": resp.StatusCode}); return
    }

    w.WriteHeader(http.StatusForbidden); _ = json.NewEncoder(w).Encode(map[string]any{"error":"policy_violation","message":"tool not permitted"})
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
    if !noHSTS { w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains") }
    if acceptBogusToken { _ = json.NewEncoder(w).Encode(map[string]any{"ok": true}); return }
    auth := r.Header.Get("Authorization")
    if !strings.HasPrefix(auth, "Bearer ") { w.WriteHeader(http.StatusUnauthorized); return }
    tok := strings.TrimPrefix(auth, "Bearer ")
    if acceptAlgNone && strings.HasSuffix(tok, ".") {
        parts := strings.Split(tok, ".")
        if len(parts) == 3 && parts[2] == "" {
            hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
            var hdr map[string]any; _ = json.Unmarshal(hb, &hdr)
            if v, ok := hdr["alg"].(string); ok && strings.EqualFold(v, "none") { _ = json.NewEncoder(w).Encode(map[string]any{"ok": true}); return }
        }
    }
    if _, err := verifyJWTRS256(tok, pubKey); err != nil { w.WriteHeader(http.StatusUnauthorized); return }
    _ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func main() {
    // Generate key
    bits := 2048
    if weakRSA { bits = 1024 }
    k, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil { log.Fatal(err) }
    privKey, pubKey, keyKid = k, &k.PublicKey, b64url([]byte("kid"+time.Now().Format(time.RFC3339)))

    mux := http.NewServeMux()
    mux.HandleFunc("/.well-known/openid-configuration", handleWellKnown)
    mux.HandleFunc("/.well-known/oauth-authorization-server", handleWellKnown)
    mux.HandleFunc("/jwks.json", handleJWKS)
    mux.HandleFunc("/register", handleRegister)
    mux.HandleFunc("/authorize", handleAuthorize)
    mux.HandleFunc("/token", handleToken)
    mux.HandleFunc("/tools", handleTools)
    mux.HandleFunc("/tool/run", handleToolRun)
    mux.HandleFunc("/", handleRoot)

    addr := ":8090"
    log.Printf("VULN MCP listening on %s (issuer %s)", addr, issuer)
    log.Printf("Vulnerabilities: GET/PUT=%v TRACE=%v missingCT=%v traversal=%v permissive=%v replay=%v bogusToken=%v algNone=%v weakRSA=%v noHSTS=%v dangerousTool=%v", allowGETPUT, allowTRACE, acceptMissingCT, allowTraversalPaths, permissiveToolRun, replayCodes, acceptBogusToken, acceptAlgNone, weakRSA, noHSTS, dangerousTool)
    log.Fatal(http.ListenAndServe(addr, mux))
}
