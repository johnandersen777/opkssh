# atproto (Bluesky)

opkssh can log in with an atproto account. It needs only the account's handle:
the PDS and authorization server are discovered from it.

```bash
opkssh login --provider 'atproto://alice.bsky.social,atproto'
```

The `atproto` after the comma fills the client ID slot and is ignored. In
`~/.opk/config.yml`:

```yaml
providers:
  - alias: bsky
    issuer: atproto://alice.bsky.social
    client_id: atproto
```

With `issuer: atproto://`, the handle is read from `$ATPROTO_HANDLE`. Login
requires the default `--key-type ecdsa`, because atproto DPoP uses ES256.

## Servers

Add the authorization server to `/etc/opk/providers` with the
`OPENPUBKEY-PKTOKEN:ATPROTO` client ID, and allow account DIDs in `auth_id`:

```bash
# /etc/opk/providers
https://bsky.social OPENPUBKEY-PKTOKEN:ATPROTO 24h

# /etc/opk/auth_id
alice did:plc:lpfuqerea3deuoyrn7ojser4 https://bsky.social
```

Certificates stop verifying after about an hour, whatever the expiration
policy, when the service auth token below expires.

## How it works

atproto OAuth has no ID token, so the PK token carries the atproto access
token. The SSH key is also the DPoP key, so the token's `cnf.jkt` claim binds
it to the SSH key.

Servers cannot check the access token's signature, because entryways such as
bsky.social do not publish their signing key. Login therefore also asks the PDS
for a service auth token (`com.atproto.server.getServiceAuth`) whose `lxm`
commits to the SSH key. The account's repo key signs it, and the account's DID
document publishes that key, so servers verify it against the DID document.

Requesting that token needs the `transition:generic` scope, so the consent
screen asks for broad access to the account.
