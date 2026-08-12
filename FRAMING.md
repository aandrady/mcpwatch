# How MCPWatch's results will be framed — written before the numbers exist

WP10's brief asks for this section to be written *before* looking at the final
numbers, so that a result cannot bend the framing afterwards. This file is
committed ahead of the analysis code that produces those numbers, and its git
history is the evidence of that ordering. It is not to be edited to fit a
result; if a finding genuinely requires a framing this document did not
anticipate, add a dated amendment below and leave the original text intact.

## What the project claims to be

An observatory, not a scanner. MCP-Scan and MCP-Scanner already read a manifest
and tell you whether it looks dangerous today. The contribution here is *time*:
the same servers, measured repeatedly, so that a change is observable at all.

The claim is therefore about **base rates and mechanics**, never about any
individual publisher's intent. "This tool's description does not mention the
network call it makes" is a statement about a description. "This publisher is
attacking users" is a statement this project's instruments cannot support and
will not make.

## The result the project is most likely to get

**Most likely: malicious mutation is rare or absent, and ordinary churn is
enormous.** The registry backfill already shows a population republishing
constantly — a median gap between versions well under a day for the busiest
publishers, and one server with over a thousand versions. Against that
background, a handful of genuinely malicious edits would be a needle in a very
large haystack, and zero of them is an entirely plausible outcome.

**That is a publishable result, and it is the one this project is designed to
survive.** Stated in advance, so it cannot later be spun as a disappointment:

> Rug pulls are a theorised threat with a taxonomy slot and, over N months and
> M servers, no measurable field base rate. Here is the observatory that would
> have caught them, here is its sensitivity, and here is what a pinning policy
> would cost you in friction for the risk it removes.

A null result with a working instrument and a quantified cost of mitigation is
more useful to a practitioner deciding whether to pin than a positive result
built from three anecdotes.

## Rules that bind regardless of what the numbers say

**1. No over-claiming from anecdotes.** If the corpus yields a small number of
genuinely malicious mutations, they are case studies, not a base rate. A
denominator is always reported beside a numerator, and a count under ~10 is
reported as a count, never as a percentage.

**2. The friction ratio is reported prominently even when it is unflattering to
pinning.** Pinning is the intuitive mitigation and this project is well placed
to price it. If the honest answer is "you will block several thousand benign
updates for every security-relevant change caught", that is the finding, and it
goes in the abstract rather than a footnote. The temptation to bury it because
pinning "feels right" is the specific failure this rule exists to prevent.

**3. Instrument limitations are reported as limitations, not as findings.** A
server MCPWatch cannot reach is a coverage gap, not a suspicious server. The
auth-required population, the nondeterministic-server quarantine, and the
package servers that will not install are all reported as denominators the
results do not cover.

**4. A proxy is never presented as ground truth.** WP6's severity flags are
"reasons to look" and are labelled as such wherever they stand in for security
relevance. Any number resting on WP7's classifier is reported with its κ, and
if the κ gate is unmet the number is labelled preliminary or withheld.

**5. Observation-window claims are bounded by the observation window.** Layer 1
has years of retrospective history. Layer 2 begins on 2026-08-07 and cannot be
backfilled. A Layer-2 rate is always reported with the number of days it covers,
and no Layer-2 rate is annualised.

**6. Nothing is named without coordinated disclosure.** Aggregate statistics are
published freely. A specific server is named only for a confirmed-malicious
case, only after the registry operator and the maintainer have had 90 days, and
never for an ambiguous one. A description that diverges from behaviour is
ambiguous by default — the likeliest explanation is a careless description, not
an attack.

## What would change the conclusion

Stated now so the bar is set before the data is in:

- **A base rate claim** needs the mutation to be adjudicated by two humans at
  κ > 0.75, not flagged by rules or labelled by a model alone.
- **A "pinning is worth it" conclusion** needs the friction ratio to be
  defensible under every policy variant tested, not the single most flattering
  one.
- **A "this was an attack" claim** needs more than divergence: an edit that
  moved capability toward exfiltration, in a server with a history, surviving
  adjudication, and disclosed before publication.

## Amendments

*None. Add dated entries here rather than editing the text above.*
