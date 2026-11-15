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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"maps"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/auth"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer = "https://bsky.social"
	testDID    = syntax.DID("did:plc:alice")
)

func newCIC(t *testing.T) (*ecdsa.PrivateKey, *clientinstance.Claims) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := jwk.PublicKeyOf(&key.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.AlgorithmKey, jwa.ES256()))
	cic, err := clientinstance.NewClaims(pub, map[string]any{})
	require.NoError(t, err)
	return key, cic
}

func jkt(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	key, err := jwk.PublicKeyOf(pub)
	require.NoError(t, err)
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(thumbprint)
}

// The authorization server binds the access token to the JWK in indigo's DPoP
// proofs; servers compare it against the CIC key. They must agree.
func TestConfigKeyBindingKeepsSSHKey(t *testing.T) {
	key, _ := newCIC(t)
	var p Provider
	require.NoError(t, p.ConfigKeyBinding(key, "ES256"))

	pub, err := p.key.PublicKey()
	require.NoError(t, err)
	dpopJWK, err := pub.JWK()
	require.NoError(t, err)
	raw, err := json.Marshal(dpopJWK)
	require.NoError(t, err)
	parsed, err := jwk.ParseKey(raw)
	require.NoError(t, err)
	require.Equal(t, jkt(t, &key.PublicKey), jkt(t, parsed))

	require.Error(t, p.ConfigKeyBinding(key, "EdDSA"))
}

func TestVerifier(t *testing.T) {
	const pds = "https://pds.example.com"
	webDID := syntax.DID("did:web:attacker.example")

	accountKey, err := atcrypto.GeneratePrivateKeyP256()
	require.NoError(t, err)
	accountPub, err := accountKey.PublicKey()
	require.NoError(t, err)
	wrongKey, err := atcrypto.GeneratePrivateKeyP256()
	require.NoError(t, err)
	dir := identity.NewMockDirectory()
	for _, did := range []syntax.DID{testDID, webDID} {
		dir.Insert(identity.Identity{
			DID:      did,
			Keys:     map[string]identity.VerificationMethod{"atproto": {Type: "Multikey", PublicKeyMultibase: accountPub.Multibase()}},
			Services: map[string]identity.ServiceEndpoint{"atproto_pds": {Type: "AtprotoPersonalDataServer", URL: pds}},
		})
	}

	sshKey, cic := newCIC(t)
	_, otherCIC := newCIC(t)

	accessToken := func(sub syntax.DID, bound *clientinstance.Claims, extra map[string]any) []byte {
		claims := map[string]any{
			"iss":   testIssuer,
			"sub":   sub,
			"aud":   "did:web:pds.example.com",
			"scope": scope,
			"exp":   time.Now().Add(time.Hour).Unix(),
			"cnf":   map[string]string{"jkt": jkt(t, bound.PublicKey())},
		}
		maps.Copy(claims, extra)
		payload, err := json.Marshal(claims)
		require.NoError(t, err)
		token, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), sshKey)) // signature is not checked
		require.NoError(t, err)
		return token
	}
	serviceAuth := func(iss syntax.DID, key atcrypto.PrivateKey, cic *clientinstance.Claims, lxm syntax.NSID) []byte {
		aud, err := audience(iss.String(), cic)
		require.NoError(t, err)
		token, err := auth.SignServiceAuth(iss, aud, time.Hour, &lxm, key)
		require.NoError(t, err)
		return []byte(token)
	}

	access := accessToken(testDID, cic, nil)
	fresh := serviceAuth(testDID, accountKey, cic, serviceAuthMethod)
	for name, tc := range map[string]struct {
		access, fresh []byte
		authServer    string
		wantErr       string
	}{
		"valid":                            {access, fresh, testIssuer, ""},
		"access token for another SSH key": {accessToken(testDID, otherCIC, nil), fresh, testIssuer, "not bound to the SSH key"},
		"forged email claim":               {accessToken(testDID, cic, map[string]any{"email": "root@example.com"}), fresh, testIssuer, `unexpected claim "email"`},
		"no service auth token":            {access, nil, testIssuer, "invalid service auth token"},
		"service auth for another SSH key": {access, serviceAuth(testDID, accountKey, otherCIC, serviceAuthMethod), testIssuer, "invalid service auth token"},
		"service auth with wrong key":      {access, serviceAuth(testDID, wrongKey, cic, serviceAuthMethod), testIssuer, "invalid service auth token"},
		"service auth for another method":  {access, serviceAuth(testDID, accountKey, cic, "com.example.other"), testIssuer, "invalid service auth token"},
		"did:web account":                  {accessToken(webDID, cic, nil), serviceAuth(webDID, accountKey, cic, serviceAuthMethod), testIssuer, "only did:plc"},
		"account on another issuer":        {access, fresh, "https://other.example", "uses authorization server https://other.example"},
	} {
		t.Run(name, func(t *testing.T) {
			v := &Verifier{issuer: testIssuer, dir: dir, authServer: func(_ context.Context, pdsURL string) (string, error) {
				require.Equal(t, pds, pdsURL)
				return tc.authServer, nil
			}}
			cicToken, err := cic.Sign(sshKey, jose.ES256, tc.access)
			require.NoError(t, err)
			pkt, err := pktoken.New(tc.access, cicToken)
			require.NoError(t, err)
			pkt.FreshIDToken = tc.fresh

			err = v.VerifyIDToken(context.Background(), tc.access, cic)
			if err == nil {
				err = v.VerifyServiceAuth(context.Background(), pkt)
			}
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}
