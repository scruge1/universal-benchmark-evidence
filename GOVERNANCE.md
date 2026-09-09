# Governance

## Authority boundaries

- A contributor pull request can add compact documents under `queue/` only.
- A queue merge is byte admission only.
- The pinned router performs signature verification and registry intake.
- An independent validator signs an acknowledgement.
- Qualification requires the request policy and distinct contributors.
- Catalog publication is a separate reviewed operation.
- No repository event can load a model, call an endpoint, or control hardware.

## Maintainer-controlled paths

Only maintainers may change `policy/`, `tools/`, `tests/`, `.github/`, root
governance files, or published snapshots. Hosted branch rules and CODEOWNERS
must reinforce this rule. Offline verification remains mandatory because hosted
settings can drift.

## Corrections

Accepted history is append-only. Do not edit, rename, or delete an accepted
queue file. Submit a new identity that names the superseded evidence when the
document contract supports that relation. Publication policy decides which
identity is current while retaining the earlier bytes.

## Key lifecycle

`policy/key-events/` is append-only. Enrollment binds a public key to one
pseudonymous reviewed principal and allowed roles. A v2 enrollment must retain
a valid short-lived SSHSIG proof of private-key possession bound to the exact
prior policy history. Possession, identity review, and role approval are three
separate checks. Revocation removes future authority but does not remove the
event or earlier signed evidence. The public-key map is derived from the
complete ordered event set. Contributor and validator roles cannot belong to
the same key or reviewed principal.

Real-person mappings and identity evidence remain outside this public
repository. Public-key comments are not identity evidence and are not retained.
Private keys never enter repository or agent custody. Each enrollment is a
separate maintainer-reviewed change; a compiled candidate has no authority.
