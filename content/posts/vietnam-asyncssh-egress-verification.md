---
title: "Coordinated Egress Verification Campaign Using SSH direct-tcpip Tunneling"
date: 2026-03-27
author: "Ethan Thomason"
tags: ["honeypot", "ssh", "threat-intel", "asyncssh", "ja4h"]
draft: false
---

## Summary

Two Vietnamese IP addresses recently conducted a coordinated SSH credential spray against a cloud-hosted honeypot. What makes this campaign notable is not the spray itself, but the post-authentication behavior: rather than deploying payloads or running recon commands, both actors used SSH `direct-tcpip` channel forwarding to tunnel HTTP requests to an IP geolocation API (`ip-who.com/json/`). Identical JA4H fingerprints across both source IPs confirm they were running the same tool simultaneously. Both IPs have nearly 500 prior abuse reports on AbuseIPDB, placing this activity in the context of a known, persistent threat.

The goal appears to be egress verification — using compromised third-party hosts as disposable vantage points to confirm that their own infrastructure's outbound IP is clean, geolocated as expected, and not flagged.

---

## Timeline

The two IPs arrived within minutes of each other and operated in parallel throughout the session. The sequence of events was identical for both:

1. Initial connection attempts with no KEX (dropped)
2. Credential spray across a mixed wordlist
3. Successful authentication
4. Immediate `direct-tcpip` tunnel to `ip-who.com:80`
5. Session closed within ~12 seconds of authentication
6. Continued credential spraying after the successful session

The continued spraying after a successful hit confirms fully automated tooling with no human in the loop.

---

## Tool Fingerprint

Both actors used `SSH-2.0-AsyncSSH_2.1.0` as their client version string. The KEX proposal is identical between both IPs and is notable for its breadth — it includes legacy algorithms that modern clients have long dropped:

- `rsa1024-sha1`, `rsa2048-sha256` (host key algorithms)
- `diffie-hellman-group1-sha1` (deprecated, Logjam-vulnerable)
- `blowfish-cbc`, `cast128-cbc`, `arcfour`, `arcfour128`, `arcfour256` (legacy ciphers)
- `curve448-sha512` (less common modern addition)

This maximally-compatible cipher list is characteristic of a purpose-built scanning tool rather than an off-the-shelf SSH client. AsyncSSH is a Python library; someone has written a custom scanner on top of it configured to negotiate with the widest possible range of targets, including old embedded devices.

**JA4H fingerprint:** `ge11nn010000_4740ae6347b0_000000000000_000000000000`

This fingerprint is **identical** across both source IPs. JA4H captures the SSH client's key exchange behavior. Matching fingerprints from two geographically distinct IPs operating in parallel is strong attribution — same binary, same configuration, same operator.

---

## Post-Authentication Behavior

Neither actor issued any shell commands. On successful authentication, each session immediately opened a `direct-tcpip` channel — SSH's built-in TCP forwarding mechanism — and sent a single HTTP request through it:

```
GET /json/ HTTP/1.1
Host: ip-who.com
```

`ip-who.com/json/` returns a JSON object containing the requesting IP's geolocation, ASN, ISP, and country. Critically, the lookup is performed **from the perspective of the compromised host**, not the attacker's true egress IP. The attacker is using your machine to ask: *what does my traffic look like from out here?*

This is egress verification — a standard operational security check for VPN operators, proxy services, or botnet operators who need to confirm that a given exit node's IP is:

1. Not flagged or blocklisted
2. Geolocated to the expected region
3. Assigned to an ISP that appears residential or benign

No payloads were staged. No persistence was established. The session ended immediately after the geolocation response was received.

---

## Credential Intelligence

Credentials that achieved access:

| IP | Username | Password |
|----|----------|----------|
| 116.110.159.95 | config | config |
| 116.99.169.248 | root | root123 |

Selected credentials from the broader spray — indicative of a mixed wordlist combining generic defaults with breach-dump replays:

- `installer`/`installer`, `ubnt`/`ubnt`, `squid`/`squid` — device/service defaults
- `ftpuser`/`asteriskftp` — VoIP/telephony defaults
- `system`/`OkwKcECs8qJP2Z` — high-entropy, clearly a breach-dump credential
- `root`/`ipscan` — possibly a self-referential credential from a prior scanner compromise
- `admin`/`0l0ctyQh243O63uD` — another high-entropy breach-dump entry

The mixture of trivial defaults and high-entropy breached credentials suggests a tiered wordlist strategy: fast-burn common defaults first, then replay breached credentials from prior campaigns.

---

## Why `direct-tcpip` Is a Useful Detection Angle

Most honeypot and SIEM alerting focuses on post-auth shell activity: command execution, file downloads, lateral movement. `direct-tcpip` tunneling to external services is a distinct and undermonitored behavior class. It requires no shell, generates no command execution events, and leaves no filesystem artifacts. In this campaign, the only post-auth events logged were channel open, JA4H capture, and tunnel data — no shell was ever spawned.

Defenders should consider alerting on `direct-tcpip` channel opens to unexpected external destinations — particularly geolocation APIs, IP reputation services, or connectivity check endpoints — as a distinct post-auth behavior class worth investigating regardless of whether shell commands follow.

---

## Indicators of Compromise

| Type | Value |
|------|-------|
| Source IP | 116.110.159.95 |
| Source IP | 116.99.169.248 |
| SSH client string | `SSH-2.0-AsyncSSH_2.1.0` |
| JA4H | `ge11nn010000_4740ae6347b0_000000000000_000000000000` |
| Tunnel destination | `ip-who.com:80` |
| Tunnel request | `GET /json/ HTTP/1.1` |
| Successful credential | `config`/`config` |
| Successful credential | `root`/`root123` |

---

## Recommendations

- Alert on `direct-tcpip` tunnels to geolocation and IP-check services post-authentication
- Add `116.110.159.95` and `116.99.169.248` to blocklists
- Consider JA4H `ge11nn010000_4740ae6347b0` as a hunt signature for this tool across other sensors
- Treat `SSH-2.0-AsyncSSH_2.1.0` combined with the legacy cipher profile above as a suspicious client fingerprint in SSH logs

---

*Both source IPs have extensive prior abuse reports on AbuseIPDB. Raw session data available on request.*
