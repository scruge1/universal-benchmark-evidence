# Universal Benchmark Evidence Exchange

- This repository is the reviewed data plane for Universal Benchmark Router.
- It carries compact signed documents. It does not carry raw benchmark logs.
- A pull-request merge admits bytes to the reviewed queue only. It does not
  bless evidence, publish a catalog, select a model, or operate a host.
- Reuse the pinned Universal Benchmark Router release for signatures, ordered
  intake, registry audit, catalog qualification, and routing semantics.
- Contributor pull requests may add files only under `queue/`.
- A maintainer key-lifecycle pull request contains exactly one added
  content-addressed event and one modified derived public-key snapshot. It must
  not contain queue data or another path.
- Never store a private key, token, endpoint credential, personal data, or
  private prompt in this repository.
- Never edit or delete an accepted queue identity. Add a new document and use
  the contract's correction mechanism.
- Run `python tools/verify_exchange.py --root .` and the test suite before
  claiming a local candidate is ready.
