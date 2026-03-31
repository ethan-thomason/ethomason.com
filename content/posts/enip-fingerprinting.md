---
title: "What's in Your CIP Sender Context? Fingerprinting Internet Scanners via EtherNet/IP"
date: 2026-03-31
author: "Ethan Thomason"
tags: ["honeypot", "otpot", "enip", "EtherNet/IP"]
draft: false
---


*This is part of an ongoing series documenting observations from otpot, an OT-focused honeypot project. If you missed the intro, [start there](https://ethomason.com/posts/otpot-intro/).*

---

otpot had been running for less than 24 hours before the first EtherNet/IP probes arrived. Censys and Shodan index everything, and a convincing Allen-Bradley 1756-L61 ControlLogix identity response is apparently interesting enough to attract regular visits.

What I didn't expect was that buried inside each of those requests was something useful: a consistent, scanner-specific value that makes it possible to identify who's knocking purely from the protocol payload — no IP intelligence required.

---

## A Quick Primer on EtherNet/IP and CIP

EtherNet/IP (Ethernet Industrial Protocol) is one of the dominant OT network protocols, used extensively in Allen-Bradley PLCs and other industrial automation equipment. It runs CIP (Common Industrial Protocol) over standard TCP/IP, which is part of why it's internet-accessible at all — it was designed for plant floor Ethernet, not isolation.

The most common unsolicited probe you'll see from internet scanners is a **List Identity** request (CIP command 0x63). It's essentially asking "what are you?" — and a real ControlLogix will respond with its vendor ID, device type, product code, revision, serial number, and product name. A honeypot like Conpot responds the same way.

The EtherNet/IP encapsulation header for these requests looks like this:

```
Command         (2 bytes)  - 0x0063 for List Identity
Length          (2 bytes)  - payload length
Session Handle  (4 bytes)  - session correlation
Status          (4 bytes)  - always 0 in requests
Sender Context  (8 bytes)  - arbitrary client-defined correlation token
Options         (4 bytes)  - always 0
```

That **Sender Context** field is where things get interesting.

---

## The Sender Context Field

The CIP specification defines the sender context as an 8-byte field that the client can use however it wants — it's echoed back in responses so the client can correlate replies to requests. In practice, most legitimate EtherNet/IP clients use it for session tracking.

Internet scanners also use it — but some of them use it consistently enough that the value itself becomes a fingerprint.

Here's what I observed in the first days of honeypot traffic.

---

## Censys: `OISYSNEC`

The first pattern I noticed was a consistent ASCII string appearing in the sender context of List Identity requests from the `66.132.172.0/24` and `66.132.195.0/24` ranges:

```
Sender Context: 4f 49 53 59 53 4e 45 43  |OISYSNEC|
```

Eight bytes, always the same, always ASCII-printable. A quick lookup confirmed these IPs belong to Censys, Inc. — the reverse DNS is `*.censys-scanner.com` and the WHOIS organization is explicitly `CENSYS-ARIN-01`.

If you stare at `OISYSNEC` for a moment and then read it backwards, you get `CENSYSIO` — almost certainly an intentional nod to Censys embedded directly in their scanner's protocol behavior. It's a small thing, but it's the kind of detail that makes you appreciate that someone at Censys thought about this.

So: **if you see `OISYSNEC` in your EtherNet/IP sender context, Censys has found your device.**

---

## Shodan: `\x00\x00\x00\x00\x6a\x0e\xbe\x64`

The second consistent pattern came from a different set of IPs — DigitalOcean droplets in the `147.182.x.x`, `143.198.x.x`, and `207.90.x.x` ranges:

```
Sender Context: 00 00 00 00 6a 0e be 64  |....j..d|
```

Not ASCII-printable, but perfectly consistent across every IP in this group. Cross-referencing these IPs confirmed they all carry `shodan.io` reverse DNS — specifically under the `*.census.shodan.io` subdomain, which is Shodan's internet census scanning infrastructure.

So: **if you see `\x00\x00\x00\x00\x6a\x0e\xbe\x64` in your EtherNet/IP sender context, Shodan has found your device.**

---

## Stretchoid: `MGLNDD_<ip>_<port>\n`

A third actor — less well-known but appearing consistently — takes a different approach entirely. Rather than a fixed context value, it sends a plaintext string as a raw TCP payload to the EtherNet/IP port:

```
MGLNDD_146.190.153.12_44818\n
```

This isn't a valid EtherNet/IP frame at all. Conpot's cpppo library can't parse it and throws an exception. But the pattern is unmistakable — `MGLNDD_` followed by the target IP and port, terminated with a newline. This is associated with Stretchoid, another internet scanning service that appears to be doing basic port fingerprinting rather than proper protocol interaction. Attribution was confirmed the same way as Censys and Shodan — reverse DNS on the source IPs resolves to `*.stretchoid.com`, hosted on Azure infrastructure.

---

## What This Means in Practice

The interesting property of these fingerprints is that they're **IP-independent**. You don't need a threat intelligence feed or a blocklist to identify scanner traffic — the sender context field tells you directly, at the protocol layer.

A few practical applications:

**For honeypot operators**, this means you can classify and filter known scanner traffic without maintaining IP lists that go stale as scanners rotate infrastructure. A simple string match on the sender context is more durable than any IP-based approach.

**For IDS/IPS rule writers**, this is a more reliable signal than IP reputation. A Suricata rule matching `OISYSNEC` in the CIP sender context field will catch Censys traffic regardless of which IP range they're scanning from that week.

**For OT defenders doing assessments**, finding either of these context values in traffic logs or PCAPs is an immediate finding: your device is visible from the internet and has been indexed by a major scanning platform. That's a conversation worth having with your client before you even run your first vulnerability scan.

**For incident responders**, being able to look at historical EtherNet/IP traffic and say "this was Shodan's census sweep, this was an unknown actor" is valuable for establishing timeline and intent.

---

## A Note on Publishing Fingerprints

Publishing protocol-level scanner fingerprints is inherently a double-edged exercise — an attacker who reads this post could trivially spoof `OISYSNEC` to make their malicious EtherNet/IP traffic blend into Censys noise. This is worth acknowledging honestly.

That said, the defensive value outweighs the risk for a few reasons. A sophisticated attacker targeting an OT network already has better evasion options than mimicking Censys, and these fingerprints aren't hard to derive independently by running your own honeypot for a few days. The operational value to defenders — improved scanner classification, more durable detection rules, better incident response context — is immediate and practical. Raising the baseline for OT network visibility is worth more than keeping fingerprints secret.

---

## Open Questions

A few things I haven't resolved yet:

- What does the Shodan context value `\x00\x00\x00\x00\x6a\x0e\xbe\x64` actually encode? The last four bytes (`6a 0e be 64`) could be a version identifier, a timestamp fragment, or something else entirely. If anyone knows, I'd like to hear it.
- Are these context values stable over time, or do Censys and Shodan rotate them? This data comes from the first days of deployment — longer-term observation would help confirm stability.
- Do other scanners (FOFA, Netlas, LeakIX) have consistent EtherNet/IP context values? I haven't seen enough traffic from those platforms yet to say.

---

## Summary

The EtherNet/IP sender context field is an 8-byte token that CIP scanners populate with consistent values — consistent enough to use as reliable scanner fingerprints:

| Context Value | Scanner | Confirmed Via |
|---|---|---|
| `OISYSNEC` (ASCII) | Censys | `*.censys-scanner.com` reverse DNS |
| `\x00\x00\x00\x00\x6a\x0e\xbe\x64` | Shodan | `*.census.shodan.io` reverse DNS |
| `MGLNDD_<ip>_<port>\n` | Stretchoid | `*.stretchoid.com` reverse DNS |

If you're running EtherNet/IP-capable equipment with any internet exposure, or if you're doing OT assessments, these values are worth adding to your detection toolkit.

---

*otpot is an open-source OT honeypot project. The code is on GitHub at [ethan-thomason/otpot](https://github.com/ethan-thomason/otpot). Feedback, additional fingerprints, and pull requests are welcome.*

