# Severities

- CRITICAL: a rootkit or backdoor is almost certainly present. Treat the host as compromised until you have explained it.
- WARN: a lead. Explain it before you trust the host; many have a legitimate cause, and the finding says what to check.
- note: context, or a check that ran clean. Read them when a CRITICAL needs explaining.

A severity is about the evidence, not about urgency to act: a CRITICAL with no remedy is still CRITICAL. In the collector queue an alert is ranked by the highest grade it ever had; a * beside it means the latest sighting was graded lower, and the detail view says why.

A missing answer is never shown as a clean one. "unknown", "DID NOT RUN" and "NOT-BUILT" each mean nobody looked, not that nothing was there.
