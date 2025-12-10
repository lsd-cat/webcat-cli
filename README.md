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

## End-to-end example (based on `demo.sh`)

The repository includes `demo.sh`, which exercises the full workflow. The commands
below mirror that script so you can quickly test the CLI end to end:

```sh
# 1) Prepare demo keys
mkdir -p keys
sigsum-key generate -o keys/key1
sigsum-key generate -o keys/key2
HEX1=$(sigsum-key to-hex -k keys/key1.pub)
HEX2=$(sigsum-key to-hex -k keys/key2.pub)

# 2) Create trust policy and app config
cat > trust_policy <<'EOF'
log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye
witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806
group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
EOF

cat > webcat.config.json <<'EOF'
{
  "app": "https://github.com/element-hq/element-web",
  "version": "1.12.3",
  "default_csp": "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'wasm-unsafe-eval'; img-src * blob: data:; connect-src * blob:; font-src 'self' data: ; media-src * blob: data:; child-src blob: data:; worker-src 'self'; frame-src blob: data:; form-action 'self'; manifest-src 'self'; frame-ancestors 'self'",
  "default_index": "index.html",
  "default_fallback": "/error.html",
  "wasm": ["8A7Ecx-qI7PnFNAOiNTRDi31wKQn06K0rm41Jv3RTvc"],
  "extra_csp": {}
}
EOF

# 3) Produce enrollment and manifest
TMPDIR=$(mktemp -d)
echo index > "$TMPDIR/index.html"
echo error > "$TMPDIR/error.html"

npm run start -- enrollment create \
  --policy-file trust_policy \
  --threshold 1 \
  --max-age 15552000 \
  --cas-url https://cas.demoelement.com \
  --signer "$HEX1" \
  --signer "$HEX2" \
  --output enrollment.json

npm run start -- manifest generate \
  --policy-file trust_policy \
  --config webcat.config.json \
  --directory "$TMPDIR" \
  --output manifest_unsigned.json

npm run start -- manifest sign \
  --policy-file trust_policy \
  -i manifest_unsigned.json \
  -k keys/key1 \
  -o manifest.json

# 4) Bundle and verify
npm run start -- bundle create --enrollment enrollment.json --manifest manifest.json --output bundle.json
npm run start -- manifest verify bundle.json
```

The script prints intermediate JSON artifacts with `jq` so you can inspect the
resulting enrollment, manifest, and bundle.

## `webcat.config.ts` schema

The manifest generator expects a Webcat config file (commonly `webcat.config.ts`
or a JSON equivalent) matching the schema below:

| Field | Type | Description |
| --- | --- | --- | --- |
| `app` | string | Origin URL of the application being packaged. |
| `version` | string | Git tag to be used for reproducibility and auditing. |
| `default_csp` | string | Base Content-Security-Policy applied to all assets. |
| `default_index` | string | Default index file served when a directory is requested; leading `/` is stripped automatically. |
| `default_fallback` | string | Absolute path served when a file is missing. |
| `wasm` | string[] | Optional list of base64url SHA-256 digests for inline WebAssembly modules. `.wasm` files are added automatically during generation. |
| `extra_csp` | Record<string, string> | Optional per-path CSP overrides; keys must start with `/`. | `{}` or `{ "/app": "default-src 'none'" }` |

Use the JSON example in the workflow above as a starting point and adjust fields
to match your application.
