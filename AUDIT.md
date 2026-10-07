# Independent Security Audit: Proposed Scope and Preparation

Updated October 7, 2026. **Status: seeking funding; independent audit not completed.**

This is a proposal for planning and discussion with independent auditors. It is not an agreed engagement, audit report, security certification or promise of a completion date.

## Internal Review Already Underway

The September preliminary AI-assisted internal review recorded nine findings (3 High, 4 Medium, 2 Low). Two High remediations and one Medium remediation have been delivered; one High remains under active remediation. One delivered remediation is verified closed, while two await final closure validation. See [SECURITY-PROGRESS.md](SECURITY-PROGRESS.md) for the dated counts, evidence summary and disclosure boundaries.

The independent engagement should review the remediation and assess the selected current implementation. Internal review and passing tests do not replace that external assessment.

## Purpose

The review should answer a practical question: **does the implementation keep readable messages and decryption keys restricted to the intended participants, including when something fails or an attacker interferes?**

It should test the implementation and its integration, rather than infer security from the use of familiar cryptographic algorithms. An audit of the two public files alone cannot establish the security of the complete service.

## Proposed Areas to Review

| Area | Questions for the reviewer |
|------|----------------------------|
| Identity and key establishment | Are peer keys authenticated? Are key changes visible? Can an attacker substitute keys or downgrade hybrid agreement without the intended checks? |
| One-to-one sessions | Are ratchet transitions, skipped messages and encrypted headers handled safely? Do malformed, duplicate and out-of-order messages preserve correct state? |
| State and delivery | Are key/state updates durable and consistent across interruption, retry, backup/restore and multiple devices? Can failures cause key reuse or misroute a message? |
| Group messages | Are signatures and membership enforced? Are sender keys rotated and distributed safely when members join or leave? |
| Local storage and recovery | Which secrets and readable caches are stored? Do PIN protection, session caches and backups meet the stated threat model? |
| Application integration | Is content encrypted before transmission? Could logs, notifications, error reports, uploads or other application paths expose readable messages or keys? |
| Voice and video, if included | Are call keys and participants authenticated? Is media encryption correctly configured, including failure and reconnection paths? This integration is not in this repository. |
| Metadata and infrastructure, if included | What identifiers and logs remain visible? Do deployed settings match privacy statements? Backend implementation is not in this repository. |

Final scope should identify exactly which of these areas are included, excluded or deferred, and what access the auditor needs.

## Preparation Before the Audit

The following are open preparation tasks, not completed checks:

- [ ] Select and freeze the exact source commits and application builds to be reviewed.
- [ ] Document correspondence between the April public snapshot and the selected current implementation; publish or provide the necessary integration code for review.
- [ ] Supply a reproducible build, pinned dependencies and the relevant runtime/platform assumptions. This repository currently has no package manifest or lockfile.
- [ ] Provide test vectors and regression coverage for key agreement, ratchet state, malformed inputs, group membership, storage and failure/retry cases. This repository currently has no automated test suite.
- [ ] Agree on the threat model, platform coverage, scope boundaries, budget and independent reviewer.
- [ ] Provide an isolated test environment and synthetic accounts/data; production secrets and private user messages should not be required.
- [ ] Agree on handling sensitive findings, remediation, retesting and publication of results.

## Proposed Public Deliverables

The intended outcome is an understandable report that identifies the audited commits/builds, review dates, methods, scope and exclusions, findings and severity, remediation status and any retest results. Publication arrangements must be agreed with the auditor, including how to handle unresolved sensitive findings responsibly.

Any later claim about an audit should link to that report and state its scope and limitations. “Audited” should not be used to suggest that every feature, later release or possible attack has been covered.

## Funding and Contact

[Sponsorship](https://support.cityofhats.com) supports open-source maintenance and the planned audit. No audit budget, auditor or schedule has been announced. Contributions do not constitute a completed review or a guarantee of security.

Auditors and potential sponsors can contact [admin@cityofhats.com](mailto:admin@cityofhats.com). For suspected vulnerabilities, use the private reporting guidance in [SECURITY.md](SECURITY.md).
