# Running the detection coverage review

## Every month

1. Export with `scripts/Export-SentinelDetectionCoverage.ps1 -SubscriptionId <id> -ResourceGroup <rg> -Workspace <name> -OutputFolder .\data -Days 30` (read-only).
2. Check `sources.csv` and `priorities.csv` are still right: a new log source, a technique that moved up after an incident or a threat report.
3. Run `python -m detcover review data --out output` and open `output/report.html`.
4. Fix the red ones first: a critical source that went silent is a fix for today, and its rules have to be run over the gap once it is back.
5. Take `detection-pack.md` to the security operations review; each decision gets an owner and a date.

## When a source comes back after a gap

1. Check the volume is back to what it was (the Log sources table).
2. Run the queries of the rules that read it over the period it was silent, by hand or as a hunt, and look at what they return.
3. Write down the gap and its cause in the incident or change record.

## Before calling a gap closed

- Enable or write the rule, map it to the technique and check its first runs in the health log.
- Test it with a safe simulation of the technique on a test machine or account, with the change approved.
- Run the review again: the technique moves to *covered* only when the rule works.

## Tuning a noisy rule

- Start from the closed incidents classified as benign or false: what do they have in common (a country, a scanner, a service account)?
- Add exclusions with an owner, a reason and an end date, or raise the threshold; never switch the rule off to make the queue shorter.
- Look at its noise again next month.

## What to keep as evidence

The pack, the CSVs and the export of the month, stored where the security team keeps its reviews.
