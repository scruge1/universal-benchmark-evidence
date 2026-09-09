# Universal Benchmark Evidence Exchange

This is the offline candidate for the public data plane used by Universal
Benchmark Router. It keeps software and evidence separate.

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

The current repository is an offline candidate. It has no real key, real
evidence, public catalog, endpoint, host, dashboard, or rig authority.

## Key enrollment

Key authority comes from append-only canonical events under
`policy/key-events/`. `policy/public-keys.json` is a derived current snapshot.
It must not be edited as an independent trust source. Compile a candidate to an
absent output, review its exact difference, then replace the snapshot only in a
maintainer-controlled change:

```text
python tools/compile_key_policy.py --root . --output public-keys.candidate.json
```

Issuer, contributor, and validator are explicit roles. A contributor and their
independent validator must use distinct keys and distinct reviewed principals.
Private keys remain outside this repository and every agent context.
