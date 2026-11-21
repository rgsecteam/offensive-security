# Playbook — Retest

Run after the client claims remediation. The goal is a defensible pass/fail per finding, not a re-assessment.

## Prerequisites

- [ ] Original `findings.yaml` and `poc/` available
- [ ] Client confirmed the fix is deployed to the tested environment
- [ ] Retest window and scope confirmed (same assets, same accounts)
- [ ] Original evidence hashes recorded

## Phase 0 — Setup

- [ ] Copy the engagement dir: `engagements/<target>-<date>-retest/`
- [ ] Copy `findings.yaml` → `findings.retest.yaml`
- [ ] Keep the original untouched
- [ ] Re-baseline the target: version, headers, WAF

## Phase 1 — Per finding

For each finding, in original severity order:

1. Replay the **exact** original PoC from `poc/F-XX/`.
2. Record: `pass` (no longer reproducible), `fail` (still reproducible), `partial`.
3. For `partial`, describe precisely what changed and what still works.
4. Test the **fix bypass**, not just the original payload:
   - WAF rule added? Try encoding, case, alternate parameter, HTTP/2.
   - Input sanitized? Try different context, different sink.
   - Authorization check added? Try method swap, version downgrade, alternate object type.
5. Look for **new** attack surface introduced by the fix (new endpoint, new parameter, debug flag).

## Phase 2 — Regression sweep

- [ ] Authentication still behaves correctly (no new bypass)
- [ ] Authorization on neighbouring objects still enforced
- [ ] No new verbose errors or stack traces
- [ ] No new open ports or services from the fix

## Phase 3 — Record

Update `findings.retest.yaml`:

```yaml
status: retest-pass | retest-fail | retest-partial
retest:
  date: 2026-11-20
  result: pass
  notes: "Original payload blocked; encoded variant also blocked."
  evidence: poc/F-01/retest-request.txt
```

## Phase 4 — Deliver

```bash
python3 ../scripts/report.py findings.retest.yaml --outdir retest-report/
```

Produce a short retest letter, not a full report:

| Finding | Original | Result | Notes |
| --- | --- | --- | --- |
| F-01 | Critical | Pass | Parameterized query confirmed |
| F-02 | High | Fail | Cross-tenant read still works with UUID |

## Decision points

- **Fix is partial** → report `partial`, state exactly what remains exploitable.
- **Fix introduces a new issue** → new finding, new ID, do not reuse the old one.
- **Client disputes the result** → attach the raw request/response with timestamps; do not argue from memory.

## Exit criteria

Every original finding has a defensible status with evidence, and the retest letter is delivered.
