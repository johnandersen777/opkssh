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

// Server-side verification for atproto login.
//
// The atproto access token's signature cannot be verified by third parties:
// entryways sign it with a key they do not publish. The PK token therefore
// carries a second JWT, obtained from the account's PDS with
// com.atproto.server.getServiceAuth. That JWT is signed by the account's repo
// signing key, which is published in the account's DID document, and its lxm
// claim commits to the client instance claims (the SSH key). Verifying the
// service auth JWT against the DID document therefore proves that the account
// owner authorized this SSH key.
//
// A providers file row opts in with this client ID marker:
//
//	https://bsky.social OPENPUBKEY-PKTOKEN:ATPROTO oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/openpubkey/opkssh/atproto"
)

const (
	atprotoClientIDMarker = "OPENPUBKEY-PKTOKEN:ATPROTO"
	atprotoMaxClockSkew   = time.Minute
)

// atprotoDirectory is a variable so tests can point DID resolution at a test
// server.
var atprotoDirectory identity.Directory = identity.DefaultDirectory()

// atprotoProviderVerifier checks the atproto access token claims and the DPoP
// key binding. It deliberately does not verify the access token signature: the
// entryway signing key is not published. verifyAtprotoFreshToken supplies the
// public, verifiable proof instead.
type atprotoProviderVerifier struct {
	issuer string
}

func (v atprotoProviderVerifier) Issuer() string { return v.issuer }

func (v atprotoProviderVerifier) VerifyIDToken(_ context.Context, idt []byte, cic *clientinstance.Claims) error {
	claims, err := atproto.DecodeJWTClaims(idt)
	if err != nil {
		return err
	}
	return atproto.VerifyAccessTokenClaims(claims, cic, v.issuer)
}

// atprotoPolicyVerifier adds the atproto service-auth check on top of the
// generic PK token verifier.
type atprotoPolicyVerifier struct {
	*verifier.Verifier
	atprotoIssuers map[string]struct{}
}

func (v *atprotoPolicyVerifier) VerifyPKToken(ctx context.Context, pkt *pktoken.PKToken, extraChecks ...verifier.Check) error {
	if err := v.Verifier.VerifyPKToken(ctx, pkt, extraChecks...); err != nil {
		return err
	}
	issuer, err := pkt.Issuer()
	if err != nil {
		return err
	}
	if _, ok := v.atprotoIssuers[issuer]; ok {
		return verifyAtprotoFreshToken(ctx, pkt)
	}
	return nil
}

// verifyAtprotoFreshToken verifies the PDS service auth JWT carried in the PK
// token's FreshIDToken field: its DID signature, its expiry, and the commit to
// the CIC in its lxm claim.
func verifyAtprotoFreshToken(ctx context.Context, pkt *pktoken.PKToken) error {
	if len(pkt.FreshIDToken) == 0 {
		return fmt.Errorf("atproto PK token is missing the service auth token")
	}
	parts := strings.Split(string(pkt.FreshIDToken), ".")
	if len(parts) != 3 {
		return fmt.Errorf("atproto service auth token is not a JWT")
	}
	claims, err := atproto.DecodeJWTClaims(pkt.FreshIDToken)
	if err != nil {
		return err
	}

	iss, _ := claims["iss"].(string)
	did, err := syntax.ParseDID(iss)
	if err != nil {
		return fmt.Errorf("atproto service auth issuer is not a DID: %w", err)
	}
	accessClaims, err := atproto.DecodeJWTClaims(pkt.OpToken)
	if err != nil {
		return err
	}
	if sub, _ := accessClaims["sub"].(string); sub != iss {
		return fmt.Errorf("atproto service auth issuer %s does not match access token subject %s", iss, sub)
	}

	exp, ok := claims["exp"].(float64)
	if !ok || time.Now().After(time.Unix(int64(exp), 0)) {
		return fmt.Errorf("atproto service auth token is expired or has no exp claim")
	}
	if iat, ok := claims["iat"].(float64); ok && time.Unix(int64(iat), 0).After(time.Now().Add(atprotoMaxClockSkew)) {
		return fmt.Errorf("atproto service auth token is issued too far in the future")
	}

	lxm, _ := claims["lxm"].(string)
	commitment, err := atproto.ParseCommitmentNSID(lxm)
	if err != nil {
		return err
	}
	cic, err := pkt.GetCicValues()
	if err != nil {
		return err
	}
	cicDigest, err := atproto.CICDigest(cic)
	if err != nil {
		return err
	}
	if !bytes.Equal(commitment, cicDigest) {
		return fmt.Errorf("atproto service auth token does not commit to this SSH key")
	}

	ident, err := atprotoDirectory.LookupDID(ctx, did)
	if err != nil {
		return fmt.Errorf("failed to resolve atproto identity %s: %w", did, err)
	}
	pub, err := ident.PublicKey()
	if err != nil {
		return fmt.Errorf("atproto identity %s has no repo signing key: %w", did, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("atproto service auth signature is malformed: %w", err)
	}
	if err := pub.HashAndVerify([]byte(parts[0]+"."+parts[1]), sig); err != nil {
		return fmt.Errorf("atproto service auth signature verification failed: %w", err)
	}
	return nil
}
