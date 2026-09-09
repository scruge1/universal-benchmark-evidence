# Contributing Evidence

Before submitting data, obtain an approved benchmark request and complete the
separate public-key enrollment review.

Submit canonical UTF-8 JSON. The filename must be the document's canonical
SHA-256 plus `.json`. Contributor pull requests may add files only in these
paths:

```text
queue/raw-manifests/
queue/requests/
queue/contributions/
queue/results/
queue/acknowledgements/
```

Submit the request first. Submit the contribution and result only after their
dependencies exist. An independent validator submits the acknowledgement in a
later pull request.

Raw data must remain outside Git. The raw manifest must bind each artifact by
locator, SHA-256, byte size, media type, disclosure class, and retention. Do not
submit code for CI to execute.

Never include private keys, tokens, credentials, private prompts, personal
data, or mutable `latest` artifact links.

