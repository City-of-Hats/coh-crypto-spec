# Security Review and Remediation Progress

Updated October 7, 2026.

In September 2026, City of Hats conducted a **preliminary AI-assisted internal security review**. The review recorded nine findings: three High, four Medium and two Low. Remediation has been delivered for two of the three High findings; the remaining High is under active remediation. Additional security hardening and compatibility work has also been recorded.

This is a maintainer-published progress summary, not an independent audit report or security certification. The review covered application implementation beyond the two files in this public repository. Its findings should not be interpreted as nine vulnerabilities in the published cryptographic modules.

## Original Review: Counts and Progress

| Severity | Findings recorded | Fixes delivered | Remediation outstanding | Delivered fixes awaiting final validation |
|----------|------------------:|----------------:|------------------------:|-----------------------------------------:|
| High | 3 | 2 | 1 | 1 |
| Medium | 4 | 1 | 3 | 1 |
| Low | 2 | 0 | 2 | 0 |
| **Total** | **9** | **3** | **6** | **2** |

**How to read the table:** findings recorded = fixes delivered + remediation outstanding. The final column is a subset of delivered fixes, not additional findings. Of the three delivered remediations, one is verified closed and two still require final closure validation. Eight findings therefore remain formally open, including those two with delivered fixes.

“Fix delivered” means remediation implementation and delivery are recorded. “Verified closed” additionally requires the finding's acceptance criteria and relevant validation evidence. The severity labels are those of the original internal review, not independently assigned ratings.

## The Three High-Severity Findings

| Finding | Progress | Public evidence summary |
|---------|----------|-------------------------|
| Legacy feature authorization | **Fixed through retirement; verified closed** | The affected legacy feature surface was retired server-side. Deployment evidence records 17 method/path rules returning HTTP 410; a September 30 read-only follow-up confirmed retirement for five checked GET operations. No affected route list or exploit procedure is published here. |
| External translation consent | **Fix delivered; final privacy validation pending** | Translation is Off by default; cloud translation requires explicit scoped consent, with a separate on-device Private mode. The recorded implementation and delivery include backend checks, isolated staging and Android native diagnostics. Remaining actual-application privacy and platform checks must be completed before formal closure. |
| High-severity finding with technical details withheld | **Open; remediation in progress** | Implementation and qualification work are underway. Affected components, vulnerable code locations, reproduction steps and exploitable conditions remain private while remediation and retesting continue. No closure or production protection is claimed for unfinished work. |

Only one of the original three High findings still requires remediation implementation. The delivered translation fix remains in the final-validation queue; it is not presented as independently audited or fully closed.

## Validation and Further Hardening

Recorded translation work includes 51 backend tests, 13 isolated staging checks and 25 Android native diagnostic assertions across six qualified runs. These are different, potentially overlapping validation scopes and are not summed into a single coverage score. Native diagnostics do not establish full application privacy, preserved-device upgrade or physical iOS qualification.

The subsequent remediation work also recorded at least 19 issue categories across implementation, compatibility and testing. These include problems found in remediation code and safely contained paths. **They are not 19 additional confirmed production vulnerabilities or 19 verified closures**, and are not added to the original nine-finding total.

The Medium remediation recorded as delivered concerns translation retention changes. Final retention validation remains pending. Details of other unresolved findings are withheld; their severity counts remain visible above.

## Evidence Dates and Scope

The totals and original severity distribution come from the September review and its September 30 status reconciliation. The October 6 continuation record keeps the remaining High finding open, with implementation qualification and rollout incomplete. The maintainer reconfirmed the two delivered High fixes and one High under remediation on October 7.

This update summarizes those records; it does not rerun tests, certify the current production deployment or independently verify closure. The detailed internal report, reproduction material and operational evidence remain private. The April cryptographic source snapshot in this repository is unchanged.

## Disclosure and Independent Review

Publishing counts and progress does not require publishing an exploit. Technical disclosure should follow remediation, retesting and consideration of affected users, consistent with [coordinated disclosure guidance](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/coordinated-disclosure).

AI-assisted internal review and regression testing help find and address problems. An independent review is still needed to assess the selected implementation, remediation and wider security claims. See the [proposed audit scope](AUDIT.md), [support the work](https://support.cityofhats.com), or use [SECURITY.md](SECURITY.md) to report a suspected vulnerability privately.
