# webcat-cli

Utilities for creating, validating, and packaging WEBCAT enrollments and manifests.

## Requirements

- Node.js 20 or newer.
- `sigsum-submit` must be available on your `$PATH` for `manifest sign` operations.
- A Sigsum trust policy and keypair for signing manifests.

## Installation

```sh
npm install
```

Run the CLI directly with `tsx` during development:

```sh
npx tsx src/cli.ts --help
```

To build the JavaScript output, run `npm run build`.

## Enrollment helpers

The `enrollment` namespace manages Sigsum enrollment payloads:

| Command | Purpose |
| --- | --- |
| `enrollment create` | Compile a Sigsum policy file and create a normalized enrollment JSON document. |
| `enrollment canonicalize` | Canonicalize an enrollment JSON document using canonical JSON rules. |
| `enrollment hash` | Canonicalize and SHA-256 hash an enrollment, outputting a base64url digest. |

Example – hash the sample enrollment definition:

```sh
npx tsx src/cli.ts enrollment hash -i examples/enrollment.json
# => TSNydkDZBv6QNZ3m7ZuBP9fFj0TD6hHDmzcwu9ulK3A
```

The canonicalized document (useful for audits) can be produced with:

```sh
npx tsx src/cli.ts enrollment canonicalize -i examples/enrollment.json
```

## Manifest helpers

The `manifest` namespace operates on WEBCAT manifests:

| Command | Purpose |
| --- | --- |
| `manifest generate` | Scan a directory of static assets, apply a manifest config, and embed a Sigsum timestamp. |
| `manifest sign` | Canonicalize a manifest body, call `sigsum-submit`, and attach the returned proof under a signer key. |
| `manifest canonicalize` | Canonicalize an existing manifest JSON document. |
| `manifest hash` | Canonicalize and SHA-256 hash a manifest, outputting a base64url digest. |
| `manifest verify` | Verify signatures in a manifest (or bundle) against an enrollment and print the policy hash. |

Example – hash the provided manifest:

```sh
npx tsx src/cli.ts manifest hash -i examples/manifest.json
# => 8OYr4SFw2U2NR2efE69FAKZicf_2QbUGxXT7kxN1C80
```

Example – verify a bundle:

```sh
npx tsx src/cli.ts manifest verify examples/bundle.json
```

## Bundle helpers

Use `bundle create` to combine an enrollment and a manifest (with signatures) into a WEBCAT bundle that can be distributed to verifiers:

```sh
npx tsx src/cli.ts bundle create -e examples/enrollment.json -m examples/manifest.json > bundle.json
```

The resulting `bundle.json` matches the fixture located in `examples/bundle.json`.

## Testing

Run the growing end-to-end test suite, which exercises the CLI against the generated examples, with:

```sh
npm test
```
