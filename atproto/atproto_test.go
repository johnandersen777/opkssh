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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/stretchr/testify/require"
)

func TestDPoPProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	op := &AtprotoOp{signer: key}

	proof, err := op.dpopProof(http.MethodPost, "https://bsky.social/oauth/par", "nonce-value", "")
	require.NoError(t, err)

	_, err = jws.Verify([]byte(proof), jws.WithKey(jwa.ES256(), &key.PublicKey))
	require.NoError(t, err)

	claims, err := DecodeJWTClaims([]byte(proof))
	require.NoError(t, err)
	require.Equal(t, "POST", claims["htm"])
	require.Equal(t, "https://bsky.social/oauth/par", claims["htu"])
	require.Equal(t, "nonce-value", claims["nonce"])
	require.NotEmpty(t, claims["jti"])
}

func TestVerifyIDToken(t *testing.T) {
	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	asKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	asJWK, err := jwk.Import(&asKey.PublicKey)
	require.NoError(t, err)
	require.NoError(t, asJWK.Set(jwk.KeyIDKey, "as-key"))
	require.NoError(t, asJWK.Set(jwk.AlgorithmKey, jwa.ES256()))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(asJWK))
	jwks, err := json.Marshal(set)
	require.NoError(t, err)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/xrpc/com.atproto.server.getSession" {
			if r.Header.Get("DPoP") == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "DPoP ") {
				http.Error(w, `{"error":"AuthenticationRequired"}`, http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"did":"did:plc:alice","handle":"alice.test"}`))
			return
		}
		_, _ = w.Write(jwks)
	}))
	defer ts.Close()

	op := &AtprotoOp{
		issuer:  ts.URL,
		jwksURI: ts.URL + "/jwks",
		pdsURL:  ts.URL,
		did:     "did:plc:alice",
		signer:  userKey,
	}
	userJWK, err := jwk.PublicKeyOf(&userKey.PublicKey)
	require.NoError(t, err)
	require.NoError(t, userJWK.Set(jwk.AlgorithmKey, jwa.ES256()))
	cic, err := clientinstance.NewClaims(userJWK, map[string]any{})
	require.NoError(t, err)

	asPrivateJWK, err := jwk.Import(asKey)
	require.NoError(t, err)
	issue := func(cnfJKT string) []byte {
		payload, err := json.Marshal(map[string]any{
			"iss":   ts.URL,
			"sub":   "did:plc:alice",
			"aud":   "did:web:pds.example.com",
			"scope": "atproto",
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(time.Hour).Unix(),
			"cnf":   map[string]any{"jkt": cnfJKT},
		})
		require.NoError(t, err)
		headers := jws.NewHeaders()
		require.NoError(t, headers.Set(jws.TypeKey, "at+jwt"))
		require.NoError(t, headers.Set(jws.KeyIDKey, "as-key"))
		token, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), asPrivateJWK, jws.WithProtectedHeaders(headers)))
		require.NoError(t, err)
		return token
	}

	userJKT, err := jwkThumbprint(&userKey.PublicKey)
	require.NoError(t, err)
	require.NoError(t, op.VerifyIDToken(context.Background(), issue(userJKT), cic))

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherJKT, err := jwkThumbprint(&otherKey.PublicKey)
	require.NoError(t, err)
	require.ErrorContains(t, op.VerifyIDToken(context.Background(), issue(otherJKT), cic), "cnf.jkt mismatch")
}
