# Changelog

This records public repository changes. It is not a changelog for the complete deployed City of Hats application.

## 2026-10-07 — Audit Preparation and Documentation Update

- Added company sponsorship tiers with no employee seat cap: US$1,000–2,499 includes 12 months of Premium for all employees; US$2,500 or more includes lifetime Premium for all current and future employees. Activation is arranged directly, and lifetime lasts as long as City of Hats offers the Premium service.

- Added opt-in supporter acknowledgment guidance and a link to the support page's supporter section; no supporter identities or payment amounts published without permission.
- Added the internal AI-assisted review progress record: 9 original findings (3 High, 4 Medium, 2 Low), with delivered remediation distinguished from outstanding work and verified closure.
- Added dated evidence summaries for delivered High remediations while withholding technical details of unresolved findings.
- Added current audit funding status and the sponsorship link.
- Configured the repository Sponsor button to link to `support.cityofhats.com`.
- Added a plain-language explanation of independent review and its limits.
- Clarified that the published cryptographic modules remain the April 2026 snapshot; current application correspondence is not verified by this update.
- Clarified limitations around metadata, Hat identity correlation, local storage protection and recipient message controls.
- Added a proposed audit scope and open preparation checklist in `AUDIT.md`.
- Added private vulnerability reporting and contribution guidance.
- Added the October documentation status and review boundaries to `PROTOCOL.md`, preserving the version 1.0 technical description.

No cryptographic source, wire format or deployed application behavior changed in this update. It is not a new cryptographic release or a completed audit.

## 2026-04-11 — Initial Publication (`v0.1.0`)

- Published `src/crypto.ts` and `src/groupCrypto.ts` with sanitized API URLs.
- Published protocol specification version 1.0, architecture documentation and the MIT license.
- Expanded the README with identity, metadata and threat-model discussion.
