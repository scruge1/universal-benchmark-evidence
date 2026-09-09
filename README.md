# Universal Benchmark Evidence Exchange

This is the public reviewed data plane used by Universal Benchmark Router. It
keeps software and evidence separate.

## Where contributor data goes

Compact signed documents go into content-addressed files under `queue/` through
pull requests. Large logs, traces, telemetry, and output archives stay in an
external artifact store. A raw manifest records their immutable locator,
SHA-256, byte size, media type, disclosure class, and retention statement.

A merge means that maintainers accepted the submitted bytes into the reviewed
queue. It does not mean that the benchmark is true or routable.

Evidence becomes catalog-eligible only after all of these gates pass:

1. the signing key was enrolled before the data pull request;
2. the request, contribution, result, and independent acknowledgement are
   valid and in order;
3. a fresh registry replay through the pinned router release passes;
4. the independent and multi-contributor qualification policy passes;
5. a separate publication review creates a versioned catalog snapshot.

## Initial maintainer workflow

The repository owner reviews and merges data pull requests. This can later use
multiple maintainers without changing the evidence rules. Key enrollment,
policy, workflow, verifier, and publication changes use a separate maintainer
path. A contributor data pull request can only add queue files.

## Local verification

Install the exact pinned dependency set, then run:

```text
python tools/verify_exchange.py --root .
python -m unittest discover -s tests -v
```

The public exchange is active as a reviewed transport but is still empty. It
has no real key, real evidence, public catalog, endpoint, host, dashboard, or
rig authority.

## Key enrollment

Key authority comes from append-only canonical events under
`policy/key-events/`. `policy/public-keys.json` is a derived current snapshot.
It must not be edited as an independent trust source. Enrollment is one event
per reviewed change and requires proof that the claimant controls the private
key. Proof of possession does not prove human identity or approve a role.

The key owner sends only one OpenSSH `ssh-ed25519` public-key file. The
maintainer uses a stable pseudonymous principal ID and compiles a short-lived
challenge into an empty candidate directory:

```text
python tools/compile_key_challenge.py --root . --public-key owner.pub --principal-id contributor-01 --role contributor --issued-at 2026-09-09T12:00:00Z --expires-at 2026-09-10T12:00:00Z --output-dir ceremony-candidate
```

The owner signs the exact generated challenge on their own system. This command
uses the fixed namespace and SHA-256 profile required by the verifier:

```text
ssh-keygen -Y sign -f /owner/private/key -n universal-benchmark-key-enrollment -O hashalg=sha256 ceremony-candidate/<challenge-sha256>.json
```

Only the challenge, detached `.sig`, and original `.pub` return to the
maintainer. Compile the event into another empty candidate directory:

```text
python tools/compile_key_event.py --root . --challenge ceremony-candidate/<challenge-sha256>.json --signature ceremony-candidate/<challenge-sha256>.json.sig --event-at 2026-09-09T12:05:00Z --reason "reviewed contributor enrollment" --output-dir event-candidate
```

Review the pseudonymous identity binding, role, challenge window, exact event,
and successful tests. Then add only that event to `policy/key-events/`, compile
the derived snapshot to an absent path, review the exact difference, and use
both files in a maintainer-controlled pull request:

```text
python tools/compile_key_policy.py --root . --output public-keys.candidate.json
```

Issuer, contributor, and validator are explicit roles. A contributor and their
independent validator must use distinct keys and distinct reviewed principals.
The public-key comment is discarded because it is not identity evidence and
can contain personal data. Private keys remain outside this repository and
every agent context.
