# Public-key policy

`key-events/` is the append-only source. `public-keys.json` is a derived
snapshot. Do not hand-edit the snapshot or place private keys here.

An enrollment event binds one raw Ed25519 public key to one pseudonymous,
separately reviewed principal and one or more roles. Schema v2 retains a
short-lived policy-bound challenge and detached SSHSIG proof of private-key
possession. Possession does not prove identity or approve a role. A revocation
event retains the public key for historical signature verification but ends
its role authority at the event time.

Use `tools/compile_key_challenge.py` and `tools/compile_key_event.py` in separate
candidate directories. Compile a candidate snapshot to an absent path with
`tools/compile_key_policy.py`. Review the event, proof, snapshot, pseudonymous
identity binding, and externally held identity record before a
maintainer-controlled policy change.
