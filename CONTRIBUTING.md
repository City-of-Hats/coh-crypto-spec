# Contributing

We welcome documentation corrections, reproducible technical questions and suggestions that help prepare the published cryptographic design for independent review.

## Start Here

Read [README.md](README.md) for source/version boundaries, [PROTOCOL.md](PROTOCOL.md) for the published design and [AUDIT.md](AUDIT.md) for open preparation tasks.

For public questions or documentation errors, [open an issue](https://github.com/City-of-Hats/coh-crypto-spec/issues) with the affected section, repository commit and a concrete example. **Report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md).**

## Pull Requests

Keep changes focused and explain the problem and resulting behavior. Distinguish proposed design changes from behavior implemented in the published source, and do not describe an unverified change as deployed or audited.

For a cryptographic code change, provide the rationale, reproducible validation, relevant test vectors and compatibility/state-migration implications. This repository is a source snapshot with no standalone build or test harness, so explain the environment used and any missing verification. Integration into this repository does not automatically update the deployed application.

Use synthetic data and sanitized examples. Do not commit credentials, private keys, tokens, account data or private messages.

## Audit Preparation

Useful contributions include a reproducible standalone build proposal, pinned dependency information, test vectors and a documented comparison with the implementation selected for audit. These remain preparation tasks until reviewed and validated; the [audit checklist](AUDIT.md#preparation-before-the-audit) records the intended work.
