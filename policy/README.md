# Public-key policy

`key-events/` is the append-only source. `public-keys.json` is a derived
snapshot. Do not hand-edit the snapshot or place private keys here.

An enrollment event binds one raw Ed25519 public key to one reviewed principal
and one or more roles. A revocation event retains the public key for historical
signature verification but ends its role authority at the event time.

Compile a candidate snapshot to an absent path with
`tools/compile_key_policy.py`. Review the event, candidate, and principal
identity before a maintainer-controlled policy change.
