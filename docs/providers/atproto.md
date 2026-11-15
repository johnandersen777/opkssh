# atproto (Bluesky) OAuth

opkssh can log in with an atproto account. The only input is the account handle;
the account's PDS and authorization server are discovered from the atproto
identity layer.

```bash
opkssh login --provider 'atproto://aliceoa.bsky.social,atproto'
```

`atproto` in the client-ID position is a placeholder. An alias may also be
configured in `~/.opk/config.yml`:

```yaml
providers:
  - alias: atproto
    issuer: atproto://aliceoa.bsky.social
    client_id: atproto
```

If the handle is omitted (`issuer: atproto://`), it is read from the
`ATPROTO_HANDLE` environment variable.

## How it works

1. The handle is resolved to a DID, and the DID document to the account's PDS.
   Handle/DID resolution and verification use
   [indigo](https://github.com/bluesky-social/indigo).
2. The PDS protected-resource metadata is resolved to the authorization server,
   and its metadata provides the PAR, authorization, token, and JWKS endpoints.
3. Login runs the atproto OAuth flow: PAR, PKCE (S256), DPoP, and a localhost
   callback. The SSH key is the DPoP key, so the access token's `cnf.jkt` claim
   binds the token to the SSH key.
4. The access token JWT is used as the PK token's OP token. It carries
   `sub` = the account DID, which is the identity presented to servers.
5. Login proves the token with `com.atproto.server.getSession` on the PDS,
   using DPoP and the `ath` claim.
6. Login requests a PDS service auth token with `lxm` set to an NSID that
   commits to the SSH key. It is stored as the PK token's second JWT; servers
   verify it against the account's DID document.

Only ES256 (the default `--key-type ecdsa`) can be used, because atproto DPoP
requires a P-256 key.

## Server support

Third parties cannot verify the atproto access token signature: entryways sign
it with a key they do not publish. During login opkssh therefore also asks the
account's PDS for a service auth token (`com.atproto.server.getServiceAuth`).
That token is signed by the account's repo signing key, which is published in
the account's DID document, and its `lxm` claim commits to the SSH key. The
token is carried in the PK token and verified by the server against the DID
document.

Enable it in `/etc/opk/providers` with the atproto client ID marker:

```bash
# Issuer Client-ID expiration-policy
https://bsky.social OPENPUBKEY-PKTOKEN:ATPROTO oidc
```

`oidc` is required (or another policy that checks the access token `exp`):
the service auth token is valid for at most one hour, so certificates expire
after about an hour.

Then authorize the account DID like any other subject:

```bash
# principal sub issuer
test did:plc:lpfuqerea3deuoyrn7ojser4 https://bsky.social
```

Because login needs the `transition:generic` scope to request the service auth
token, the consent screen grants the client broad PDS access. Login requests
that scope explicitly.
