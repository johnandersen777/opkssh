// Copyright 2026 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package atproto

// atproto OAuth provider.
//
// atproto has no OpenID ID Token, so the atproto access token (a JWT with
// sub=<DID> and cnf.jkt=<DPoP key thumbprint>) is used as the PK token's OP
// token. The DPoP key is the same ES256 key as the SSH key, so the access
// token's cnf claim proves possession of the SSH key. The PDS is located from
// the handle through the atproto identity layer: handle -> DID -> DID document
// -> PDS -> authorization server.
//
// ponytail: opkssh servers only know OIDC issuers, so a verifier for the
// atproto authorization server (JWKS at jwks_uri, cnf.jkt commitment) is
// needed before stock servers accept these certs.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
)

const (
	atprotoRequiredScope = "atproto"
	// transition:generic is needed to request a service auth token with a
	// custom lxm (the commitment to the SSH key).
	atprotoScope        = "atproto transition:generic"
	atprotoCallbackPath = "/callback"
	atprotoFlowTimeout  = 5 * time.Minute
	// atprotoCommitmentPrefix is the NSID prefix carrying the CIC commitment.
	atprotoCommitmentPrefix = "com.opkssh."
)

type AtprotoOp struct {
	util.OutOrErrWriter

	handle      string
	did         string
	pdsURL      string
	issuer      string
	jwksURI     string
	authURL     string
	tokenURL    string
	parURL      string
	openBrowser bool
	httpClient  *http.Client
	finder      discover.PublicKeyFinder

	// signer is the SSH key, configured by ConfigKeyBinding. It also signs
	// the DPoP proofs, binding the access token to the SSH key.
	signer crypto.Signer
	// serviceAuth is a PDS-signed service auth JWT whose lxm commits to the
	// CIC. It is attached to the PK token for server-side verification.
	serviceAuth []byte
}

var _ providers.OpenIdProvider = (*AtprotoOp)(nil)
var _ providers.KeyBindingOpenIdProvider = (*AtprotoOp)(nil)

type atprotoServerMeta struct {
	Issuer                             string `json:"issuer"`
	AuthorizationEndpoint              string `json:"authorization_endpoint"`
	TokenEndpoint                      string `json:"token_endpoint"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`
	JwksURI                            string `json:"jwks_uri"`
}

// NewAtprotoOp resolves handle to its PDS and authorization server.
func NewAtprotoOp(handle string, openBrowser bool) (*AtprotoOp, error) {
	o := &AtprotoOp{
		handle:      strings.TrimSpace(handle),
		openBrowser: openBrowser,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
	if err := o.discover(context.Background()); err != nil {
		return nil, err
	}
	o.finder = discover.PublicKeyFinder{
		JwksFunc: func(ctx context.Context, _ string) ([]byte, error) {
			return o.fetchJWKS(ctx)
		},
	}
	return o, nil
}

func (o *AtprotoOp) discover(ctx context.Context) error {
	if o.handle == "" {
		o.handle = os.Getenv("ATPROTO_HANDLE")
	}

	// Resolve the handle through the atproto identity layer. indigo verifies
	// the handle/DID mapping in both directions and extracts the PDS service
	// from the DID document.
	ident, err := identity.DefaultDirectory().LookupHandle(ctx, syntax.Handle(o.handle))
	if err != nil {
		return fmt.Errorf("failed to resolve atproto handle %s: %w", o.handle, err)
	}
	o.did = ident.DID.String()

	pdsURL := strings.TrimSuffix(ident.PDSEndpoint(), "/")
	u, err := url.Parse(pdsURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("DID document for %s has no valid PDS endpoint (%q)", o.did, pdsURL)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
		return fmt.Errorf("PDS endpoint must be https: %s", pdsURL)
	}
	o.pdsURL = pdsURL

	asURL, err := o.resolveAuthorizationServer(ctx, pdsURL)
	if err != nil {
		return fmt.Errorf("failed to resolve authorization server for %s: %w", pdsURL, err)
	}
	meta, err := o.fetchServerMeta(ctx, asURL)
	if err != nil {
		return err
	}
	o.issuer = meta.Issuer
	o.authURL = meta.AuthorizationEndpoint
	o.tokenURL = meta.TokenEndpoint
	o.parURL = meta.PushedAuthorizationRequestEndpoint
	o.jwksURI = meta.JwksURI
	return nil
}

func (o *AtprotoOp) resolveAuthorizationServer(ctx context.Context, pdsURL string) (string, error) {
	body, status, err := o.get(ctx, pdsURL+"/.well-known/oauth-protected-resource")
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("protected resource metadata returned HTTP %d: %s", status, body)
	}
	var prm struct {
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(body, &prm); err != nil {
		return "", err
	}
	if len(prm.AuthorizationServers) != 1 {
		return "", fmt.Errorf("expected one authorization server, got %d", len(prm.AuthorizationServers))
	}
	asURL := strings.TrimSuffix(prm.AuthorizationServers[0], "/")
	u, err := url.Parse(asURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
		return "", fmt.Errorf("invalid authorization server %q", prm.AuthorizationServers[0])
	}
	return asURL, nil
}

func (o *AtprotoOp) fetchServerMeta(ctx context.Context, asURL string) (*atprotoServerMeta, error) {
	body, status, err := o.get(ctx, asURL+"/.well-known/oauth-authorization-server")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("authorization server metadata returned HTTP %d: %s", status, body)
	}
	var meta atprotoServerMeta
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, err
	}
	if strings.TrimSuffix(meta.Issuer, "/") != asURL {
		return nil, fmt.Errorf("authorization server issuer %q does not match %q", meta.Issuer, asURL)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" || meta.PushedAuthorizationRequestEndpoint == "" || meta.JwksURI == "" {
		return nil, fmt.Errorf("authorization server metadata is missing required endpoints")
	}
	for name, endpoint := range map[string]string{
		"authorization_endpoint":                meta.AuthorizationEndpoint,
		"token_endpoint":                        meta.TokenEndpoint,
		"pushed_authorization_request_endpoint": meta.PushedAuthorizationRequestEndpoint,
		"jwks_uri":                              meta.JwksURI,
	} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("authorization server metadata has invalid %s %q", name, endpoint)
		}
	}
	return &meta, nil
}

func (o *AtprotoOp) Issuer() string { return o.issuer }

func (o *AtprotoOp) ConfigKeyBinding(kbSigner crypto.Signer, kbAlg string) error {
	if kbAlg != "ES256" {
		return fmt.Errorf("atproto login requires --key-type ecdsa (ES256), got %s", kbAlg)
	}
	key, ok := kbSigner.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return fmt.Errorf("atproto login requires a P-256 ECDSA key")
	}
	o.signer = kbSigner
	return nil
}

// RequestTokens runs atproto's PAR + PKCE + DPoP browser flow and returns the
// access token JWT as the OP token.
func (o *AtprotoOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	key, ok := o.signer.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("atproto login requires a P-256 ECDSA key (use --key-type ecdsa)")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d%s", port, atprotoCallbackPath)
	clientID := "http://localhost?redirect_uri=" + url.QueryEscape(redirectURI) + "&scope=" + atprotoScope

	verifier := randB64(32)
	challenge := sha256.Sum256([]byte(verifier))
	state := randB64(16)

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(atprotoCallbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			errCh <- fmt.Errorf("atproto authorization failed: %s: %s", e, q.Get("error_description"))
			http.Error(w, "Login failed. You can close this window.", http.StatusBadRequest)
			return
		}
		if q.Get("state") != state {
			errCh <- fmt.Errorf("atproto authorization state mismatch")
			http.Error(w, "Login failed. You can close this window.", http.StatusBadRequest)
			return
		}
		codeCh <- q.Get("code")
		fmt.Fprint(w, "Login complete. You can close this window.")
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	form := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {atprotoScope},
		"state":                 {state},
		"code_challenge":        {b64(challenge[:])},
		"code_challenge_method": {"S256"},
		"login_hint":            {o.handle},
		"dpop_jkt":              {atprotoJKT(&key.PublicKey)},
	}
	var par struct {
		RequestURI string `json:"request_uri"`
	}
	nonce, err := o.postForm(ctx, o.parURL, form, &par)
	if err != nil {
		return nil, fmt.Errorf("atproto PAR request failed: %w", err)
	}

	authURL := o.authURL + "?" + url.Values{
		"client_id":   {clientID},
		"request_uri": {par.RequestURI},
	}.Encode()
	if o.openBrowser {
		fmt.Fprintf(o.OutWriter(), "Opening browser to %s\n", authURL)
		if err := util.OpenUrl(authURL); err != nil {
			fmt.Fprintf(o.ErrWriter(), "Failed to open URL: %v\n", err)
			fmt.Fprintf(o.OutWriter(), "Open your browser to: %s\n", authURL)
		}
	} else {
		fmt.Fprintf(o.OutWriter(), "Open your browser to: %s\n", authURL)
	}

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(atprotoFlowTimeout):
		return nil, fmt.Errorf("timed out waiting for atproto authorization callback")
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		Sub          string `json:"sub"`
	}
	_, err = o.postForm(ctx, o.tokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}, &tok, nonce)
	if err != nil {
		return nil, fmt.Errorf("atproto token request failed: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("atproto token response did not include an access token")
	}
	if tok.Sub != "" && tok.Sub != o.did {
		return nil, fmt.Errorf("atproto token is for %s, expected %s", tok.Sub, o.did)
	}
	if !strings.Contains(tok.Scope, atprotoRequiredScope) {
		return nil, fmt.Errorf("atproto token is missing the %s scope", atprotoRequiredScope)
	}

	// A service auth token is signed by the account's repo signing key, which
	// is published in the DID document. Its lxm claim carries the CIC hash, so
	// servers can verify the commitment without access to the AS signing key.
	if err := o.requestServiceAuth(ctx, tok.AccessToken, cic); err != nil {
		return nil, fmt.Errorf("atproto service auth request failed: %w", err)
	}

	return &simpleoidc.Tokens{
		IDToken:      []byte(tok.AccessToken),
		AccessToken:  []byte(tok.AccessToken),
		RefreshToken: []byte(tok.RefreshToken),
	}, nil
}

// AttachServiceAuth stores the service auth token in the PK token's
// FreshIDToken field, which the compact encoding carries to servers.
func (o *AtprotoOp) AttachServiceAuth(pkt *pktoken.PKToken) error {
	if len(o.serviceAuth) == 0 {
		return fmt.Errorf("atproto service auth token missing")
	}
	pkt.FreshIDToken = o.serviceAuth
	return nil
}

// requestServiceAuth asks the PDS for a service auth JWT whose lxm commits to
// the CIC. The token is signed by the account's repo signing key, so it can be
// verified offline against the account's DID document.
func (o *AtprotoOp) requestServiceAuth(ctx context.Context, accessToken string, cic *clientinstance.Claims) error {
	hash, err := cic.Hash()
	if err != nil {
		return err
	}
	// cic.Hash() is base64url text; use the raw digest so the NSID name
	// segment stays under its 63-character limit.
	digest, err := base64.RawURLEncoding.DecodeString(string(hash))
	if err != nil {
		return err
	}
	lxm := atprotoCommitmentPrefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest))

	endpoint := o.pdsURL + "/xrpc/com.atproto.server.getServiceAuth"
	query := url.Values{
		"aud": {o.did},
		"lxm": {lxm},
		"exp": {strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
	}
	body, err := o.pdsGet(ctx, endpoint, query, accessToken)
	if err != nil {
		return err
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return err
	}
	if out.Token == "" {
		return fmt.Errorf("PDS returned an empty service auth token")
	}
	o.serviceAuth = []byte(out.Token)
	return nil
}

func (o *AtprotoOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return o.finder.ByKeyID(ctx, o.issuer, keyID, false)
}

func (o *AtprotoOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return o.finder.ByToken(ctx, o.issuer, token, false)
}

// VerifyIDToken verifies the atproto access token's issuer, expiry, subject,
// and cnf.jkt key binding. Signature verification is best-effort: some
// authorization servers sign access tokens with a symmetric HMAC key and
// publish an empty JWKS, making them opaque to clients. In that case the token
// is trusted because it was read directly from the token endpoint response
// over TLS, and its cnf claim still proves possession of the SSH key.
func (o *AtprotoOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	alg, err := jwtHeaderAlg(idt)
	if err != nil {
		return err
	}

	jwks, err := o.fetchJWKS(ctx)
	if err != nil {
		return err
	}
	if hasJWKSKeys(jwks) {
		set, err := jwk.Parse(jwks)
		if err != nil {
			return fmt.Errorf("failed to parse atproto JWKS: %w", err)
		}
		if _, err := jws.Verify(idt, jws.WithKeySet(set, jws.WithRequireKid(false))); err != nil {
			return fmt.Errorf("atproto access token signature verification failed: %w", err)
		}
	} else if !strings.HasPrefix(alg, "HS") && alg != "ES256K" {
		// ES256K is what atproto entryways use; HS* tokens are also opaque to
		// clients by design. checkSession below is the real proof for both.
		return fmt.Errorf("atproto JWKS is empty and cannot verify %s access token", alg)
	}

	claims, err := jwtClaims(idt)
	if err != nil {
		return err
	}
	if iss, _ := claims["iss"].(string); iss != o.issuer {
		return fmt.Errorf("atproto access token issuer %q does not match %q", iss, o.issuer)
	}
	if exp, ok := claims["exp"].(float64); !ok || time.Now().After(time.Unix(int64(exp), 0)) {
		return fmt.Errorf("atproto access token is expired or has no exp claim")
	}
	if sub, _ := claims["sub"].(string); sub != o.did {
		return fmt.Errorf("atproto access token subject %q does not match %q", sub, o.did)
	}
	if aud, _ := claims["aud"].(string); aud == "" {
		return fmt.Errorf("atproto access token has no aud claim")
	}
	if scope, _ := claims["scope"].(string); !strings.Contains(scope, atprotoRequiredScope) {
		return fmt.Errorf("atproto access token is missing the %s scope", atprotoRequiredScope)
	}

	cnf, _ := claims["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	if jkt == "" {
		return fmt.Errorf("atproto access token has no cnf.jkt claim")
	}
	cicJWK, err := jwk.PublicKeyOf(cic.PublicKey())
	if err != nil {
		return err
	}
	thumbprint, err := cicJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	if b64(thumbprint) != jkt {
		return fmt.Errorf("atproto access token is not bound to the SSH key (cnf.jkt mismatch)")
	}

	// Authorization servers may sign access tokens with a key they do not
	// publish (e.g. an entryway ES256K key), so the token is opaque to the
	// client. Prove it is valid and bound to the SSH key by calling the PDS
	// with a DPoP proof: only the holder of the key in cnf.jkt can do that.
	if err := o.checkSession(ctx, idt); err != nil {
		return fmt.Errorf("atproto session check failed: %w", err)
	}
	return nil
}

// checkSession calls com.atproto.server.getSession on the PDS with the access
// token and a DPoP proof signed by the SSH key. This also confirms the token's
// audience is the PDS resolved from the handle.
func (o *AtprotoOp) checkSession(ctx context.Context, accessToken []byte) error {
	endpoint := o.pdsURL + "/xrpc/com.atproto.server.getSession"
	body, err := o.pdsGet(ctx, endpoint, nil, string(accessToken))
	if err != nil {
		return err
	}
	var session struct {
		DID string `json:"did"`
	}
	if err := json.Unmarshal(body, &session); err != nil {
		return err
	}
	if session.DID != o.did {
		return fmt.Errorf("PDS session is for %s, expected %s", session.DID, o.did)
	}
	return nil
}

// pdsGet sends a DPoP-authenticated GET to a PDS XRPC endpoint, retrying once
// with the server's DPoP nonce.
func (o *AtprotoOp) pdsGet(ctx context.Context, endpoint string, query url.Values, accessToken string) ([]byte, error) {
	fullURL := endpoint
	if len(query) > 0 {
		fullURL += "?" + query.Encode()
	}
	nonce := ""
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return nil, err
		}
		// cnf-bound access tokens must use the DPoP authorization scheme
		// (RFC 9449 section 7.1), not Bearer.
		req.Header.Set("Authorization", "DPoP "+accessToken)
		// htu excludes the query string; ath hashes the access token.
		proof, err := o.dpopProof(http.MethodGet, endpoint, nonce, accessToken)
		if err != nil {
			return nil, err
		}
		req.Header.Set("DPoP", proof)
		if nonce != "" {
			req.Header.Set("DPoP-Nonce", nonce)
		}
		resp, err := o.httpClientOrDefault().Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 == 2 {
			return body, nil
		}
		if newNonce := resp.Header.Get("DPoP-Nonce"); newNonce != "" && attempt == 0 {
			nonce = newNonce
			continue
		}
		return nil, oauthError(resp.StatusCode, body)
	}
	return nil, fmt.Errorf("PDS rejected the DPoP proof")
}

func (o *AtprotoOp) fetchJWKS(ctx context.Context) ([]byte, error) {
	body, status, err := o.get(ctx, o.jwksURI)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("atproto JWKS returned HTTP %d", status)
	}
	return body, nil
}

// postForm posts form and decodes the JSON response, retrying once with the
// server's DPoP nonce when the server answers use_dpop_nonce.
func (o *AtprotoOp) postForm(ctx context.Context, endpoint string, form url.Values, out any, nonces ...string) (string, error) {
	nonce := ""
	if len(nonces) > 0 {
		nonce = nonces[0]
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		resp, body, err := o.do(ctx, http.MethodPost, endpoint, form, nonce)
		if err != nil {
			return "", err
		}
		if resp.Header.Get("DPoP-Nonce") != "" {
			nonce = resp.Header.Get("DPoP-Nonce")
		}
		if resp.StatusCode/100 == 2 {
			if err := json.Unmarshal(body, out); err != nil {
				return "", err
			}
			return nonce, nil
		}
		lastErr = oauthError(resp.StatusCode, body)
		if !strings.Contains(lastErr.Error(), "use_dpop_nonce") {
			break
		}
	}
	return "", lastErr
}

func oauthError(status int, body []byte) error {
	var e struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		description := e.ErrorDescription
		if description == "" {
			description = e.Message
		}
		return fmt.Errorf("%s: %s (HTTP %d)", e.Error, description, status)
	}
	return fmt.Errorf("HTTP %d: %s", status, strings.TrimSpace(string(body)))
}

func (o *AtprotoOp) httpClientOrDefault() *http.Client {
	if o.httpClient == nil {
		return http.DefaultClient
	}
	return o.httpClient
}

func (o *AtprotoOp) do(ctx context.Context, method, endpoint string, form url.Values, nonce string) (*http.Response, []byte, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, nil, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	proof, err := o.dpopProof(method, endpoint, nonce)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("DPoP", proof)
	if nonce != "" {
		req.Header.Set("DPoP-Nonce", nonce)
	}
	resp, err := o.httpClientOrDefault().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, respBody, nil
}

func (o *AtprotoOp) get(ctx context.Context, endpoint string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := o.httpClientOrDefault().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func (o *AtprotoOp) dpopProof(method, endpoint, nonce string, accessToken ...string) (string, error) {
	key, ok := o.signer.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return "", fmt.Errorf("atproto DPoP requires a P-256 ECDSA key")
	}
	claims := map[string]any{
		"jti": randB64(16),
		"htm": method,
		"htu": endpoint,
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	// Resource-server requests must carry ath, the hash of the access token
	// (RFC 9449 section 4.2).
	if len(accessToken) > 0 && accessToken[0] != "" {
		sum := sha256.Sum256([]byte(accessToken[0]))
		claims["ath"] = b64(sum[:])
	}
	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": atprotoJWK(&key.PublicKey),
	}
	return signES256(key, header, claims)
}

func atprotoJWK(pub *ecdsa.PublicKey) map[string]string {
	x, y := ecCoords(pub)
	return map[string]string{"kty": "EC", "crv": "P-256", "x": x, "y": y}
}

// atprotoJKT is the RFC 7638 thumbprint used as the DPoP key binding.
func atprotoJKT(pub *ecdsa.PublicKey) string {
	x, y := ecCoords(pub)
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, x, y)
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:])
}

// ecCoords returns the base64url P-256 coordinates from the uncompressed
// SEC1 public key encoding (0x04 || X || Y).
func ecCoords(pub *ecdsa.PublicKey) (string, string) {
	raw, err := pub.Bytes()
	if err != nil || len(raw) != 65 || raw[0] != 4 {
		panic("atproto: not an uncompressed P-256 public key")
	}
	return b64(raw[1:33]), b64(raw[33:65])
}

func signES256(key *ecdsa.PrivateKey, header, claims any) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(headerJSON) + "." + b64(claimsJSON)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64(sig), nil
}

func jwtClaims(token []byte) (map[string]any, error) {
	payload, err := jwtPart(token, 1)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func jwtHeaderAlg(token []byte) (string, error) {
	header, err := jwtPart(token, 0)
	if err != nil {
		return "", err
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(header, &h); err != nil || h.Alg == "" {
		return "", fmt.Errorf("atproto access token has no alg header")
	}
	return h.Alg, nil
}

func jwtPart(token []byte, i int) ([]byte, error) {
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("atproto access token is not a JWT")
	}
	return base64.RawURLEncoding.DecodeString(parts[i])
}

func hasJWKSKeys(jwks []byte) bool {
	var out struct {
		Keys []json.RawMessage `json:"keys"`
	}
	return json.Unmarshal(jwks, &out) == nil && len(out.Keys) > 0
}

func randB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b64(b)
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
