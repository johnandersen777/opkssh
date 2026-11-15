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

package policy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/stretchr/testify/require"
)

const testAtprotoIssuer = "https://bsky.social"

func b64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unsignedJWT(header, claims map[string]any) []byte {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	return []byte(b64URL(h) + "." + b64URL(c) + "." + b64URL([]byte("sig")))
}

func signServiceJWT(t *testing.T, key *atcrypto.PrivateKeyP256, claims map[string]any) []byte {
	header, _ := json.Marshal(map[string]any{"typ": "JWT", "alg": "ES256"})
	payload, _ := json.Marshal(claims)
	input := b64URL(header) + "." + b64URL(payload)
	sig, err := key.HashAndSign([]byte(input))
	require.NoError(t, err)
	return []byte(input + "." + b64URL(sig))
}

func TestAtprotoPolicyVerifier(t *testing.T) {
	ctx := context.Background()
	did := "did:plc:testalice"

	acctKey, err := atcrypto.GeneratePrivateKeyP256()
	require.NoError(t, err)
	acctPub, err := acctKey.PublicKey()
	require.NoError(t, err)

	didDoc := map[string]any{
		"id": did,
		"verificationMethod": []any{map[string]any{
			"id":                 did + "#atproto",
			"type":               "Multikey",
			"controller":         did,
			"publicKeyMultibase": acctPub.Multibase(),
		}},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/"+did, r.URL.Path)
		_ = json.NewEncoder(w).Encode(didDoc)
	}))
	defer ts.Close()
	oldDir := atprotoDirectory
	atprotoDirectory = &identity.BaseDirectory{PLCURL: ts.URL, SkipHandleVerification: true}
	defer func() { atprotoDirectory = oldDir }()

	// SSH key and CIC
	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	userJWK, err := jwk.PublicKeyOf(&userKey.PublicKey)
	require.NoError(t, err)
	require.NoError(t, userJWK.Set(jwk.AlgorithmKey, jose.ES256))
	cic, err := clientinstance.NewClaims(userJWK, map[string]any{})
	require.NoError(t, err)
	thumbprint, err := userJWK.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken := unsignedJWT(
		map[string]any{"alg": "ES256K", "typ": "at+jwt"},
		map[string]any{
			"iss":   testAtprotoIssuer,
			"sub":   did,
			"aud":   "did:web:pds.example.com",
			"scope": "atproto transition:generic",
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(time.Hour).Unix(),
			"cnf":   map[string]any{"jkt": b64URL(thumbprint)},
		},
	)
	cicToken, err := cic.Sign(userKey, jose.ES256, accessToken)
	require.NoError(t, err)
	pkt, err := pktoken.New(accessToken, cicToken)
	require.NoError(t, err)

	cicHash, err := cic.Hash()
	require.NoError(t, err)
	cicDigest, err := base64.RawURLEncoding.DecodeString(string(cicHash))
	require.NoError(t, err)
	lxm := atprotoCommitmentPrefix + lowerBase32(cicDigest)

	serviceClaims := map[string]any{
		"iss": did,
		"aud": did,
		"lxm": lxm,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"jti": "test-jti",
	}
	pkt.FreshIDToken = signServiceJWT(t, acctKey, serviceClaims)

	provider := atprotoProviderVerifier{issuer: testAtprotoIssuer}
	require.NoError(t, provider.VerifyIDToken(ctx, accessToken, cic))

	base, err := verifier.NewFromMany([]verifier.ProviderVerifier{
		verifier.ProviderVerifierExpires{
			ProviderVerifier: provider,
			Expiration:       verifier.ExpirationPolicies.OIDC,
		},
	})
	require.NoError(t, err)
	v := &atprotoPolicyVerifier{
		Verifier:       base,
		atprotoIssuers: map[string]struct{}{testAtprotoIssuer: {}},
	}
	require.NoError(t, v.VerifyPKToken(ctx, pkt))

	// A service auth token committing to a different key must fail.
	wrongDigest := make([]byte, len(cicDigest))
	copy(wrongDigest, cicDigest)
	wrongDigest[0] ^= 0xff
	bad := map[string]any{}
	for k, val := range serviceClaims {
		bad[k] = val
	}
	bad["lxm"] = atprotoCommitmentPrefix + lowerBase32(wrongDigest)
	pkt.FreshIDToken = signServiceJWT(t, acctKey, bad)
	require.ErrorContains(t, v.VerifyPKToken(ctx, pkt), "does not commit")

	// A tampered signature must fail.
	pkt.FreshIDToken = signServiceJWT(t, acctKey, serviceClaims)
	parts := strings.Split(string(pkt.FreshIDToken), ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	sig[0] ^= 0xff
	pkt.FreshIDToken = []byte(parts[0] + "." + parts[1] + "." + b64URL(sig))
	require.Error(t, v.VerifyPKToken(ctx, pkt))
}

func lowerBase32(b []byte) string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}
