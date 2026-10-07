# Security Reporting

## Report a Suspected Vulnerability Privately

Email [admin@cityofhats.com](mailto:admin@cityofhats.com) with the subject **City of Hats security report**. Avoid posting exploit details in a public issue before we have had an opportunity to investigate.

Useful information includes:

- The repository commit or application version and affected platform.
- A description of the issue, expected behavior and potential impact.
- Minimal reproduction steps using synthetic accounts and data.
- Any relevant sanitized logs or a small proof of concept.

Do not include passwords, private keys, tokens or other users' messages. If sensitive evidence is necessary, first ask how to provide it securely; ordinary email is not an encrypted evidence channel.

Please keep testing to systems and accounts you own or are explicitly authorized to assess. A reporting contact does not authorize access to other users' data or production infrastructure.

## Review Status and Version Scope

The public cryptographic source is the April 2026 snapshot. The October 7, 2026 update changes documentation only; it is not a security patch or verification of the current deployed application. There is no maintained security-support matrix for releases in this repository.

An independent audit has not been completed. See [AUDIT.md](AUDIT.md) for the proposed review and preparation work. No response-time guarantee or paid bug bounty is announced here.

The [security progress summary](SECURITY-PROGRESS.md) records the preliminary AI-assisted internal review and remediation counts. Sensitive technical details of unresolved findings remain private while fixes and validation continue. A delivered fix is not described as independently verified closure.
