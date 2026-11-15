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
	"crypto"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

const (
	// RequiredScope identifies an atproto OAuth session.
	RequiredScope = "atproto"
	// Scopes is what login requests. transition:generic is required to ask
	// the PDS for a service auth token with a custom lxm.
	Scopes = "atproto transition:generic"
	// CommitmentPrefix is the NSID prefix carrying the CIC commitment.
	CommitmentPrefix = "com.opkssh."
)

// DecodeJWTClaims decodes a compact JWT payload without verifying its
// signature.
func DecodeJWTClaims(token []byte) (map[string]any, error) {
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("atproto token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// VerifyAccessTokenClaims checks the atproto access token claims shared by the
// login client and the server verifier. The access token signature is not
// checked here: entryways may use a signing key they do not publish.
func VerifyAccessTokenClaims(claims map[string]any, cic *clientinstance.Claims, issuer string) error {
	if iss, _ := claims["iss"].(string); iss != issuer {
		return fmt.Errorf("atproto access token issuer %q does not match %q", iss, issuer)
	}
	if exp, ok := claims["exp"].(float64); !ok || time.Now().After(time.Unix(int64(exp), 0)) {
		return fmt.Errorf("atproto access token is expired or has no exp claim")
	}
	sub, _ := claims["sub"].(string)
	if _, err := syntax.ParseDID(sub); err != nil {
		return fmt.Errorf("atproto access token sub is not a DID: %w", err)
	}
	if aud, _ := claims["aud"].(string); !strings.HasPrefix(aud, "did:") {
		return fmt.Errorf("atproto access token aud is not a DID")
	}
	if scope, _ := claims["scope"].(string); !strings.Contains(scope, RequiredScope) {
		return fmt.Errorf("atproto access token is missing the %s scope", RequiredScope)
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
	return nil
}

// CICDigest returns the raw CIC commitment digest. cic.Hash returns base64url
// text, which is too long once encoded into an NSID name segment.
func CICDigest(cic *clientinstance.Claims) ([]byte, error) {
	hash, err := cic.Hash()
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(string(hash))
}

// CommitmentNSID encodes a CIC digest as the NSID carried in the service auth
// token's lxm claim. base32 keeps it within the 63-character name segment.
func CommitmentNSID(digest []byte) string {
	return CommitmentPrefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest))
}

// ParseCommitmentNSID reverses CommitmentNSID.
func ParseCommitmentNSID(lxm string) ([]byte, error) {
	encoded, found := strings.CutPrefix(lxm, CommitmentPrefix)
	if !found {
		return nil, fmt.Errorf("atproto service auth token lxm does not carry a commitment")
	}
	commitment, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return nil, fmt.Errorf("atproto service auth lxm commitment is malformed: %w", err)
	}
	return commitment, nil
}
