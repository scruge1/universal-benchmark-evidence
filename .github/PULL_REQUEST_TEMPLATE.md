## Change class

- [ ] Queue-only contributor data
- [ ] Maintainer key enrollment or revocation
- [ ] Maintainer control-plane change

## Exact identities

List every added content-addressed filename and its purpose.

## Review evidence

- [ ] I changed no accepted queue or key-event identity.
- [ ] I included no private key, credential, personal data, private prompt, or
      mutable raw-artifact link.
- [ ] The local exchange verifier and complete test suite pass.

For key enrollment only:

- [ ] This pull request contains exactly one new v2 enrollment event and the
      exact derived public-key snapshot.
- [ ] The SSHSIG proof uses namespace
      `universal-benchmark-key-enrollment` and SHA-256.
- [ ] The challenge binds the current policy ancestry and has not expired.
- [ ] Proof of possession, external identity review, and role approval were
      checked separately.
- [ ] Contributor and validator keys and reviewed principals remain distinct.
