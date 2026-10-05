# Security review

The publisher and dependency installer were reviewed on 2026-10-05. The private HTTP API is outside this public repository; its existing authorization regression checks remain in the private project.

## Fixed and tested

- Build subprocesses receive only required runtime settings and exact branch metadata. Service credentials and authentication-agent variables are excluded.
- Artifact publication rejects traversal and symlink paths before reading or writing outside the artifact directory.
- Signing rejects non-Ed25519 keys and preserves the previous feed on failure.
- Worker and installer downloads enforce HTTPS, trusted hosts, standard TLS ports, byte limits and total time limits. Credentials in download URLs are rejected.
- Dependency archives require verified SHA-256 values. Extraction blocks escaping paths and links, oversized expanded archives and oversized package indexes.
- A retry verifies and reuses a JAR left by an interrupted publication instead of overwriting an immutable artifact.
- Relative configuration resolves from its own directory. Logs and private settings use restricted file permissions.

Existing checks cover branch/commit selection, release tag ancestry, digest rejection, exact signed payload bytes, feed limits and atomic replacement.

## Remaining trust boundary

Gradle executes code from the trusted source branch as the worker account. Environment filtering does not isolate the signing key from malicious code running under that same account. Review source commits and protect that account and its signing key. This setup does not provide a separate build sandbox.

Release verification authenticates the downloaded bytes and metadata; it does not prove that executable code is harmless. Only trusted branches and reviewed releases belong in this pipeline.

Back up the signing key privately. A key change requires a separately distributed client build that trusts the new public key. No private keys or user tokens belong in issues, logs or this repository.
