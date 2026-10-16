<!--
  cyberdeck-arsenal :: executive_summary.md
  ===========================================================================
  Reference template for the one-page executive summary.

  `report_generator.py --formats exec` writes an EXECUTIVE_SUMMARY.md derived
  from the same data. This file documents the intended structure and can be
  copied as the basis for a bespoke summary: keep it to one page, avoid jargon,
  and always lead with the business impact rather than the technical detail.

  Tokens used here are documentation examples, not substitutions:
    {{CLIENT}} {{GENERATED}} {{TESTER}} {{SCOPE}} {{RISK}} {{VERSION}}
  ===========================================================================
-->
# Executive summary: {{CLIENT}}

**Assessment date:** {{GENERATED}}
**Prepared by:** {{TESTER}}
**Overall risk rating:** {{RISK}}

## What we did

We assessed {{SCOPE}} over the agreed window. Testing combined passive
reconnaissance, network and service enumeration, targeted vulnerability checks,
and manual verification of every high-impact result. A few sentences are enough:
the reader should know what was tested, how, and what was out of scope.

## What we found

State the outcome in plain language first: "three issues could allow an
attacker to access customer data without a password" is more useful than
"multiple CVEs were identified". Include:

- The single most serious issue, in one sentence, with its business impact.
- How many issues were found, grouped by severity.
- Whether any issue is currently being exploited (usually unknown: say so).
- What was *not* found, so the reader knows the limits of the assessment.

## What to fix first

| Priority | Action | Owner (suggested) | Target date |
|---|---|---|---|
| 1 | Fix the highest-severity issue identified above | IT / Infrastructure | within 72 hours |
| 2 | Address remaining high-severity findings | IT / Infrastructure | within 14 days |
| 3 | Address medium findings | IT / Infrastructure | within 30 days |
| 4 | Address low findings and hardening items | IT / Infrastructure | within 90 days |

## What happens next

1. Confirm the findings with the technical team and agree accountable owners.
2. Remediate in priority order; contact us if any fix needs advice.
3. We re-test to confirm the fixes and issue a short confirmation letter.

## Assurance and limitations

Testing was time-boxed and performed against the systems reachable at the time.
It was not exhaustive: the absence of a finding is not evidence that a
vulnerability does not exist. Configuration, patch levels and the network
topology may have changed since the assessment was carried out.

---

The full technical report, including evidence, command output and detailed
remediation steps, accompanies this summary. Artefact hashes are recorded in an
append-only chain-of-custody log so results can be independently verified.
