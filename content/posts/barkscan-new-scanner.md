---
title: "First Documentation of BarkScan_1.0: A New Internet Scanner with an Identity Problem"
date: 2026-03-26
lastmod: 2026-04-02
tags: ["threat-intelligence", "honeypot", "scanning", "greynoise"]
description: "A new commercial internet scanner appeared in my honeypot logs with no prior documentation anywhere. What followed was an interesting exercise in distinguishing legitimate research infrastructure from malicious actors -- and the answer wasn't clean."
---

On March 26, 2026, my Cowrie SSH honeypot logged an SSH client version string I'd never seen before and couldn't find documented anywhere: `SSH-2.0-BarkScan_1.0`. What followed was a few hours of investigation that surfaced a new commercial internet scanner with a legitimate-looking website, an anonymous team, and a globally-flagged malicious IP -- and no clean answer on which description was more accurate.

This appears to be the first public documentation of the BarkScan_1.0 banner string. GreyNoise subsequently reviewed the IP and escalated it internally as high priority.

---

## The Initial Finding

The banner appeared among a routine day's worth of honeypot traffic. Running `SSH-2.0-BarkScan_1.0` through the usual sources -- ISC SANS diary archives, Cowrie community discussions, threat intel databases -- returned nothing. The banner string had no paper trail.

The source IP was **185.107.80.93**, hosted on NForce Entertainment B.V. (AS43350) in the Netherlands. NForce is a Dutch hosting provider with a reputation for permissive abuse handling -- a common home for both legitimate scanner infrastructure and malicious actors.

The IP reputation data told an immediately conflicted story:

| Source | Assessment |
|--------|------------|
| AbuseIPDB | 3,678 reports |
| GreyNoise | **Malicious** -- actor unknown, last seen 2026-03-26 |
| Shodan | "BarkScan -- Security Research Scanner" |

GreyNoise and Shodan were in direct disagreement. That's worth investigating.

---

## What Is BarkScan?

Fetching `http://185.107.80.93` returned a scanner self-identification page -- standard practice for legitimate operators like Shodan, Censys, and ZGrab. The page identified the operator as **BarkScan**, a commercial internet intelligence platform positioning itself as a Shodan/Censys competitor. The pitch: scanning 5 billion services across 65,000 ports, starting at $9/month.

The server headers dated the page to **February 11, 2026** -- but as discussed below, that date is misleading.

The about page described a team of "security engineers frustrated with the state of internet intelligence tooling." But several things were missing:

- No named founders or team members
- No LinkedIn presence
- Twitter and GitHub footer links were dead (`href="#"`)
- Domain registration was privacy-protected

For comparison: Shodan is associated with John Matherly. Censys was founded by researchers at the University of Michigan who published their work. ZGrab is maintained by the Censys team with full institutional transparency. BarkScan offered none of this.

---

## The Historical Baggage

URLScan.io showed the IP previously hosted **imgmaze.pw** approximately six years prior -- an image hosting site with its own abuse history. This explains the bulk of the 3,678 AbuseIPDB reports, which predate BarkScan's existence by years.

IP recycling is common and unremarkable on its own. When a hosting provider reassigns an IP, the new tenant inherits whatever reputation the previous occupant left behind. A legitimate operator in this situation would typically either work through the delisting processes with AbuseIPDB, GreyNoise, and relevant blocklists, or simply get a fresh IP -- which costs a few additional dollars a month from any VPS provider.

A Wayback Machine search of `barkscan.com` complicates the timeline further. The domain was first crawled in November 2024 (returning a 404), but by **January 18, 2025** the site was live -- and what it was doing then is worth noting. The January 2025 version is a **subdomain enumeration tool**: a simple search interface prompting "Enter domain to find subdomains," with Home, Login, and Sign Up navigation. Not an internet-wide scanner. Not a Shodan competitor.

The logo is identical to the current site. Same brand, completely different product.

The domain was saved seven times through July 10, 2025. The February 2026 server last-modified date reflects a page refresh following a product pivot -- not the project's launch. BarkScan has been operating under this brand for at least 14 months, and its rebranding as an internet-wide SSH scanner is a more recent development layered on top of that history.

This is where the analysis gets interesting.

---

## The Analytical Tension

BarkScan presents itself as a professional commercial platform with paying customers, tiered pricing, and a polished marketing site. A company in that position has concrete business incentives to maintain clean scanning infrastructure: their product only works if their scanner IPs can actually reach internet hosts without being auto-blocked by security tools.

Delisting processes exist and work. GreyNoise responds to "new tenant, please reassess" requests. AbuseIPDB scores decay with time. NForce IPs are cheap to replace. A competent commercial operator would know this and act on it.

The fact that BarkScan has been operating since at least January 2025 -- over 14 months -- while running from an IP with 3,678 AbuseIPDB reports and a GreyNoise malicious classification is inconsistent with the professional security company framing. A project running for over a year has had ample time to discover and remediate a dirty IP. It suggests one of two possibilities:

1. The operator is aware but doesn't care whether their traffic gets blocked
2. The GreyNoise malicious classification reflects current behavior rather than just inherited history

I can't determine which with confidence. What I can note is that the behavioral evidence and the stated identity don't fully align.

---

## GreyNoise Analysis

After submitting this finding through GreyNoise's community tag request process and posting to r/AskNetsec, a GreyNoise team member responded publicly with their analysis. They escalated it internally as high priority for actor tagging, and were unambiguous that a benign classification was unlikely.

Their behavioral history for the IP told a more complete story than the current classification suggests. The longer lookback -- going back to early February 2026 -- included tags for **TLS/SSL Crawler**, **Web Crawler**, **SSH Connection Attempt**, **SSH Alternative Port Crawler**, **SSH Bruteforcer**, **Generic Path Traversal Attempt**, and **Generic Sensitive File Access Attempt**. The latter three are not scanner noise -- they are unambiguously offensive behaviors.

The more recent window (late February onward) showed lower-confidence activity described as generic web crawling, which likely explains the current **suspicious** classification rather than outright malicious. That behavioral shift -- from active brute-forcing and path traversal to quieter crawling -- is itself worth noting. Operators sometimes throttle activity after attracting attention.

The GreyNoise analyst also independently flagged the dead GitHub link on the landing page as a credibility signal, consistent with the findings above. Their recommendation was to block the IP and the user agent string regardless of classification.

As of April 2, 2026, GreyNoise shows the IP classified as **suspicious** with tags for TLS/SSL Crawler, Web Crawler, SSH Connection Attempt, and SSH Alternative Port Crawler. Actor tagging is pending.

---

## Indicators

```
Client banner : SSH-2.0-BarkScan_1.0
Scanner IP    : 185.107.80.93
ASN           : AS43350 / NForce Entertainment B.V., Netherlands
Org domain    : barkscan.com
Web server    : nginx/1.24.0 (Ubuntu)
Page modified : Wed, 11 Feb 2026 14:09:12 GMT
```

The original GitHub Gist documenting this finding (published 2026-03-26 under my prior research handle) is available at:
`https://gist.github.com/spicybandit78/ac057216292170926ca3d0fc4387ab22`

---

## Takeaways

A few things worth carrying forward from this investigation:

**Self-identification pages don't establish legitimacy.** The Shodan/Censys model of scanner self-identification is valuable and I respect operators who do it. But the existence of a polished landing page with an opt-out form doesn't verify the operator's identity or intent. The bar for "legitimate research scanner" is more than a nice-looking website.

**Product pivots are worth tracking.** A brand that started as a subdomain enumeration tool and quietly relaunched as an internet-wide scanner -- without updating its public narrative -- is exhibiting the kind of opacity that warrants scrutiny regardless of intent.

**Classifications change as behavior accumulates.** The shift from malicious to suspicious between the observation date and today reflects GreyNoise's ongoing analysis of the IP's behavior, not a contradiction. Reading the full behavioral history matters more than the current label.

**New scanner infrastructure is worth documenting even when conclusions are uncertain.** The value of publishing this finding wasn't a definitive verdict on BarkScan -- it was establishing a timestamped record of the banner string and the IP, giving the community something to build on. That's how threat intelligence accumulates.

If you've observed `SSH-2.0-BarkScan_1.0` in your own honeypot logs, I'd be interested to hear about it.

---

*Ethan Thomason runs CedarTech, an OT/ICS systems integration firm in the Sacramento area, and maintains a network of honeypots as an independent security research project.*
