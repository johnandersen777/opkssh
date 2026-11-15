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

// Package atproto implements opkssh login with atproto (Bluesky) OAuth.
//
// atproto OAuth issues no ID token, so the PK token carries the atproto access
// token as its OP token. The SSH key is also the DPoP key, so the access
// token's cnf.jkt claim binds it to the SSH key.
//
// SSH servers cannot check the access token's signature: entryways such as
// bsky.social sign it with a key they do not publish. Login therefore also
// asks the PDS for a service auth token whose lxm claim commits to the SSH key.
// It is signed by the account's repo key, which the account's DID document
// publishes, so servers can verify it. It travels in the PK token's
// FreshIDToken field.
package atproto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
)

const (
	// transition:generic lets the session request a service auth token with
	// a custom lxm.
	scope        = "atproto transition:generic"
	callbackPath = "/callback"
	flowTimeout  = 5 * time.Minute
)

var errUnpublishedKey = errors.New("atproto: access token signing keys are not published")

// Provider logs in to an atproto account.
type Provider struct {
	util.OutOrErrWriter

	handle      syntax.Handle
	did         syntax.DID
	pdsURL      string
	meta        *oauth.AuthServerMetadata
	openBrowser bool

	key         *atcrypto.PrivateKeyP256 // the SSH key, also the DPoP key
	serviceAuth []byte
}

var (
	_ providers.OpenIdProvider           = (*Provider)(nil)
	_ providers.KeyBindingOpenIdProvider = (*Provider)(nil)
)

// New resolves handle to its DID, PDS and authorization server. An empty
// handle is read from $ATPROTO_HANDLE.
func New(handle string, openBrowser bool) (*Provider, error) {
	if handle == "" {
		handle = os.Getenv("ATPROTO_HANDLE")
	}
	h, err := syntax.ParseHandle(handle)
	if err != nil {
		return nil, fmt.Errorf("atproto: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ident, err := identity.DefaultDirectory().LookupHandle(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("atproto: resolving %s: %w", h, err)
	}
	pdsURL := ident.PDSEndpoint()
	resolver := oauth.NewResolver()
	asURL, err := resolver.ResolveAuthServerURL(ctx, pdsURL)
	if err != nil {
		return nil, fmt.Errorf("atproto: resolving authorization server for %s: %w", h, err)
	}
	meta, err := resolver.ResolveAuthServerMetadata(ctx, asURL)
	if err != nil {
		return nil, fmt.Errorf("atproto: %w", err)
	}
	return &Provider{handle: h, did: ident.DID, pdsURL: pdsURL, meta: meta, openBrowser: openBrowser}, nil
}

func (p *Provider) Issuer() string { return p.meta.Issuer }

// ConfigKeyBinding makes the SSH key the DPoP key. atproto DPoP needs ES256.
func (p *Provider) ConfigKeyBinding(signer crypto.Signer, alg string) error {
	key, ok := signer.(*ecdsa.PrivateKey)
	if !ok || alg != "ES256" {
		return errors.New("atproto: login requires an ES256 key (--key-type ecdsa)")
	}
	raw, err := key.Bytes()
	if err != nil {
		return err
	}
	p.key, err = atcrypto.ParsePrivateBytesP256(raw)
	return err
}

// RequestTokens runs the atproto OAuth flow in the browser and returns the
// access token as the OP token. It also fetches the service auth token that
// commits to cic.
func (p *Provider) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	if p.key == nil {
		return nil, errors.New("atproto: no DPoP key configured")
	}
	ctx, cancel := context.WithTimeout(ctx, flowTimeout)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	callbacks := make(chan url.Values, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+callbackPath, func(w http.ResponseWriter, r *http.Request) {
		select {
		case callbacks <- r.URL.Query():
		default:
		}
		fmt.Fprintln(w, "You can close this window.")
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	cfg := oauth.NewLocalhostConfig("http://"+ln.Addr().String()+callbackPath, strings.Fields(scope))
	app := oauth.NewClientApp(&cfg, nil)

	// PKCE verifiers need at least 43 characters; rand.Text returns 26.
	verifier, state := rand.Text()+rand.Text(), rand.Text()
	requestURI, nonce, err := p.pushAuthRequest(ctx, app.Client, url.Values{
		"client_id":             {cfg.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {cfg.CallbackURL},
		"scope":                 {scope},
		"state":                 {state},
		"code_challenge":        {oauth.S256CodeChallenge(verifier)},
		"code_challenge_method": {"S256"},
		"login_hint":            {p.handle.String()},
	})
	if err != nil {
		return nil, err
	}

	authURL := p.meta.AuthorizationEndpoint + "?" + url.Values{
		"client_id":   {cfg.ClientID},
		"request_uri": {requestURI},
	}.Encode()
	fmt.Fprintf(p.OutWriter(), "Open your browser to: %s\n", authURL)
	if p.openBrowser {
		if err := util.OpenUrl(authURL); err != nil {
			fmt.Fprintf(p.ErrWriter(), "Failed to open browser: %v\n", err)
		}
	}

	var q url.Values
	select {
	case q = <-callbacks:
	case <-ctx.Done():
		return nil, fmt.Errorf("atproto: waiting for authorization: %w", ctx.Err())
	}
	switch {
	case q.Get("error") != "":
		return nil, fmt.Errorf("atproto: authorization failed: %s: %s", q.Get("error"), q.Get("error_description"))
	case q.Get("state") != state:
		return nil, errors.New("atproto: authorization state mismatch")
	case q.Get("iss") != p.meta.Issuer:
		return nil, errors.New("atproto: authorization issuer mismatch")
	}

	tok, err := app.SendInitialTokenRequest(ctx, q.Get("code"), oauth.AuthRequestData{
		AuthServerTokenEndpoint: p.meta.TokenEndpoint,
		PKCEVerifier:            verifier,
		DPoPAuthServerNonce:     nonce,
		DPoPPrivateKeyMultibase: p.key.Multibase(),
	})
	if err != nil {
		return nil, fmt.Errorf("atproto: %w", err)
	}
	if tok.Subject != p.did.String() {
		return nil, fmt.Errorf("atproto: token issued for %s, expected %s", tok.Subject, p.did)
	}

	if p.serviceAuth, err = p.fetchServiceAuth(ctx, app, tok.AccessToken, cic); err != nil {
		return nil, err
	}
	return &simpleoidc.Tokens{
		IDToken:      []byte(tok.AccessToken),
		AccessToken:  []byte(tok.AccessToken),
		RefreshToken: []byte(tok.RefreshToken),
	}, nil
}

// pushAuthRequest sends the PAR request with a DPoP proof from the SSH key,
// retrying once with the server's DPoP nonce. indigo's PAR helper cannot be
// used because it generates its own DPoP key. It returns the request URI and
// the server's latest nonce.
func (p *Provider) pushAuthRequest(ctx context.Context, client *http.Client, form url.Values) (string, string, error) {
	endpoint := p.meta.PushedAuthorizationRequestEndpoint
	var nonce string
	for attempt := 0; ; attempt++ {
		proof, err := oauth.NewAuthDPoP(http.MethodPost, endpoint, nonce, p.key)
		if err != nil {
			return "", "", err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return "", "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", proof)

		resp, err := client.Do(req)
		if err != nil {
			return "", "", err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			return "", "", err
		}

		next := resp.Header.Get("DPoP-Nonce")
		if resp.StatusCode == http.StatusBadRequest && next != nonce && attempt == 0 {
			nonce = next
			continue
		}
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return "", "", fmt.Errorf("atproto: PAR request failed: HTTP %d: %s", resp.StatusCode, body)
		}
		var par oauth.PushedAuthResponse
		if err := json.Unmarshal(body, &par); err != nil {
			return "", "", fmt.Errorf("atproto: PAR response: %w", err)
		}
		return par.RequestURI, next, nil
	}
}

// fetchServiceAuth asks the PDS for a service auth token whose lxm commits to
// cic.
func (p *Provider) fetchServiceAuth(ctx context.Context, app *oauth.ClientApp, accessToken string, cic *clientinstance.Claims) ([]byte, error) {
	lxm, err := commitment(cic)
	if err != nil {
		return nil, err
	}
	sess := &oauth.ClientSession{
		Client: app.Client,
		Config: app.Config,
		Data: &oauth.ClientSessionData{
			AccountDID:    p.did,
			HostURL:       p.pdsURL,
			AuthServerURL: p.meta.Issuer,
			AccessToken:   accessToken,
		},
		DPoPPrivateKey:         p.key,
		PersistSessionCallback: func(context.Context, *oauth.ClientSessionData) {},
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := sess.APIClient().Get(ctx, "com.atproto.server.getServiceAuth", map[string]any{
		"aud": p.did.String(),
		"lxm": lxm.String(),
		// The PDS caps tokens with an lxm at one hour; leave room for skew.
		"exp": time.Now().Add(59 * time.Minute).Unix(),
	}, &out); err != nil {
		return nil, fmt.Errorf("atproto: getServiceAuth: %w", err)
	}
	return []byte(out.Token), nil
}

// AttachServiceAuth stores the service auth token from RequestTokens in pkt,
// which carries it to SSH servers.
func (p *Provider) AttachServiceAuth(pkt *pktoken.PKToken) {
	pkt.FreshIDToken = p.serviceAuth
}

// VerifyIDToken checks the access token RequestTokens just received.
func (p *Provider) VerifyIDToken(_ context.Context, idt []byte, cic *clientinstance.Claims) error {
	claims, err := verifyAccessToken(idt, cic, p.Issuer())
	if err != nil {
		return err
	}
	if claims.Sub != p.did.String() {
		return fmt.Errorf("atproto: access token is for %s, expected %s", claims.Sub, p.did)
	}
	return nil
}

func (p *Provider) PublicKeyByKeyId(context.Context, string) (*discover.PublicKeyRecord, error) {
	return nil, errUnpublishedKey
}

func (p *Provider) PublicKeyByToken(context.Context, []byte) (*discover.PublicKeyRecord, error) {
	return nil, errUnpublishedKey
}
