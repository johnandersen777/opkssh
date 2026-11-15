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

import (
	"context"
	"crypto"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/bluesky-social/indigo/atproto/auth"
	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

// serviceAuthMethod is the lxm of the service auth token login requests. Only
// opkssh accepts it, so login's scope grants just this method, for any
// audience.
const serviceAuthMethod = syntax.NSID("com.opkssh.sshLogin")

// accessTokenClaims lists the claims atproto access tokens carry. Servers
// cannot check the token's signature, and policy reads claims from it, so any
// other claim (email, groups, ...) would be chosen by the client.
var accessTokenClaims = []string{"iss", "sub", "aud", "exp", "iat", "jti", "scope", "cnf", "client_id"}

// Verifier verifies atproto PK tokens on SSH servers.
type Verifier struct {
	issuer     string
	dir        identity.Directory
	authServer func(ctx context.Context, pdsURL string) (string, error)
}

// NewVerifier returns a Verifier for accounts whose PDS uses the authorization
// server issuer, such as https://bsky.social.
func NewVerifier(issuer string) *Verifier {
	return &Verifier{
		issuer:     issuer,
		dir:        identity.DefaultDirectory(),
		authServer: oauth.NewResolver().ResolveAuthServerURL,
	}
}

func (v *Verifier) Issuer() string { return v.issuer }

// VerifyIDToken checks that the access token is consistent with the SSH key.
// Its signature cannot be checked, so VerifyServiceAuth provides the proof.
func (v *Verifier) VerifyIDToken(_ context.Context, idt []byte, cic *clientinstance.Claims) error {
	_, err := verifyAccessToken(idt, cic, v.issuer)
	return err
}

// VerifyServiceAuth verifies the service auth token in pkt: it must be signed
// by the DID key of the access token's subject, be for serviceAuthMethod,
// unexpired, and its audience must commit to pkt's CIC. The subject's PDS must
// use v's authorization server.
func (v *Verifier) VerifyServiceAuth(ctx context.Context, pkt *pktoken.PKToken) error {
	var access accessToken
	if err := json.Unmarshal(pkt.Payload, &access); err != nil {
		return err
	}
	cic, err := pkt.GetCicValues()
	if err != nil {
		return err
	}
	aud, err := audience(access.Sub, cic)
	if err != nil {
		return err
	}
	dir := plcOnly{v.dir}
	validator := auth.ServiceAuthValidator{Audience: aud, Dir: dir}
	method := serviceAuthMethod
	did, err := validator.Validate(ctx, string(pkt.FreshIDToken), &method)
	if err != nil {
		return fmt.Errorf("atproto: invalid service auth token: %w", err)
	}
	if did.String() != access.Sub {
		return fmt.Errorf("atproto: service auth token issued by %s, expected %s", did, access.Sub)
	}

	// The access token's iss is unsigned, so bind the issuer through the DID
	// document instead: the account's PDS must use this authorization server.
	ident, err := dir.LookupDID(ctx, did)
	if err != nil {
		return fmt.Errorf("atproto: resolving %s: %w", did, err)
	}
	asURL, err := v.authServer(ctx, ident.PDSEndpoint())
	if err != nil {
		return fmt.Errorf("atproto: resolving authorization server of %s: %w", did, err)
	}
	if asURL != v.issuer {
		return fmt.Errorf("atproto: %s uses authorization server %s, expected %s", did, asURL, v.issuer)
	}
	return nil
}

// plcOnly resolves only did:plc identities, from plc.directory. Resolving a
// did:web would make the server fetch from a host an unauthenticated client
// chose.
//
// ponytail: did:web accounts cannot log in; add an opt-in if they must.
type plcOnly struct{ identity.Directory }

func (d plcOnly) LookupDID(ctx context.Context, did syntax.DID) (*identity.Identity, error) {
	if did.Method() != "plc" {
		return nil, fmt.Errorf("atproto: %s: only did:plc accounts are supported", did)
	}
	return d.Directory.LookupDID(ctx, did)
}

type accessToken struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Cnf struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
}

// verifyAccessToken checks an access token's claims, without its signature,
// and that its DPoP key (cnf.jkt) is the CIC key.
func verifyAccessToken(token []byte, cic *clientinstance.Claims, issuer string) (*accessToken, error) {
	msg, err := jws.Parse(token)
	if err != nil {
		return nil, fmt.Errorf("atproto: parsing access token: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(msg.Payload(), &raw); err != nil {
		return nil, fmt.Errorf("atproto: parsing access token: %w", err)
	}
	for name := range raw {
		if !slices.Contains(accessTokenClaims, name) {
			return nil, fmt.Errorf("atproto: access token has unexpected claim %q", name)
		}
	}
	var claims accessToken
	if err := json.Unmarshal(msg.Payload(), &claims); err != nil {
		return nil, fmt.Errorf("atproto: parsing access token: %w", err)
	}
	if claims.Iss != issuer {
		return nil, fmt.Errorf("atproto: access token issuer is %q, expected %q", claims.Iss, issuer)
	}
	key, err := jwk.PublicKeyOf(cic.PublicKey())
	if err != nil {
		return nil, err
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	if claims.Cnf.JKT != base64.RawURLEncoding.EncodeToString(thumbprint) {
		return nil, errors.New("atproto: access token is not bound to the SSH key")
	}
	return &claims, nil
}

// audience returns the service auth audience that commits to cic: the account
// DID with the base32 CIC hash as its fragment, a DID reference getServiceAuth
// accepts.
func audience(did string, cic *clientinstance.Claims) (string, error) {
	hash, err := cic.Hash() // base64url text of a SHA3-256 digest
	if err != nil {
		return "", err
	}
	digest, err := base64.RawURLEncoding.DecodeString(string(hash))
	if err != nil {
		return "", err
	}
	return did + "#" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest), nil
}
