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
	ctx := context.Background()
	accountKey, err := atcrypto.GeneratePrivateKeyP256()
	require.NoError(t, err)
	accountPub, err := accountKey.PublicKey()
	require.NoError(t, err)
	dir := identity.NewMockDirectory()
	dir.Insert(identity.Identity{
		DID: testDID,
		Keys: map[string]identity.VerificationMethod{
			"atproto": {Type: "Multikey", PublicKeyMultibase: accountPub.Multibase()},
		},
	})
	v := &Verifier{issuer: testIssuer, dir: dir}

	sshKey, cic := newCIC(t)
	_, otherCIC := newCIC(t)

	accessToken := func(cnfKey crypto.PublicKey) []byte {
		payload, err := json.Marshal(map[string]any{
			"iss":   testIssuer,
			"sub":   testDID,
			"aud":   "did:web:pds.example.com",
			"scope": scope,
			"exp":   time.Now().Add(time.Hour).Unix(),
			"cnf":   map[string]string{"jkt": jkt(t, cnfKey)},
		})
		require.NoError(t, err)
		token, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), sshKey)) // signature is not checked
		require.NoError(t, err)
		return token
	}
	serviceAuth := func(key atcrypto.PrivateKey, cic *clientinstance.Claims, lxm syntax.NSID) []byte {
		aud, err := audience(testDID.String(), cic)
		require.NoError(t, err)
		token, err := auth.SignServiceAuth(testDID, aud, time.Hour, &lxm, key)
		require.NoError(t, err)
		return []byte(token)
	}
	pkToken := func(access, fresh []byte) *pktoken.PKToken {
		cicToken, err := cic.Sign(sshKey, jose.ES256, access)
		require.NoError(t, err)
		pkt, err := pktoken.New(access, cicToken)
		require.NoError(t, err)
		pkt.FreshIDToken = fresh
		return pkt
	}

	valid := accessToken(cic.PublicKey())
	require.NoError(t, v.VerifyIDToken(ctx, valid, cic))
	require.ErrorContains(t, v.VerifyIDToken(ctx, accessToken(otherCIC.PublicKey()), cic), "not bound to the SSH key")

	wrongKey, err := atcrypto.GeneratePrivateKeyP256()
	require.NoError(t, err)
	for name, tc := range map[string]struct {
		fresh   []byte
		wantErr string
	}{
		"valid":         {serviceAuth(accountKey, cic, serviceAuthMethod), ""},
		"missing":       {nil, "invalid service auth token"},
		"other SSH key": {serviceAuth(accountKey, otherCIC, serviceAuthMethod), "invalid service auth token"},
		"wrong signer":  {serviceAuth(wrongKey, cic, serviceAuthMethod), "invalid service auth token"},
		"wrong method":  {serviceAuth(accountKey, cic, "com.example.other"), "invalid service auth token"},
	} {
		t.Run(name, func(t *testing.T) {
			err := v.VerifyServiceAuth(ctx, pkToken(valid, tc.fresh))
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}
