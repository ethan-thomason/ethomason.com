---
title: "Compromised MikroTik Routers Used as Proxy Nodes — Caught Using My Honeypot to Check Their Own IP"
date: 2026-04-02
draft: false
tags: ["honeypot", "threat-intel", "mikrotik", "botnet", "cowrie", "proxy", "vietnam"]
description: "Two Vietnamese MikroTik routers with 100% AbuseIPDB confidence attempted to use my Cowrie honeypot as a proxy to query their own external IP address. Shodan confirms the devices are compromised residential routers running RouterOS 7.18.2 — a pattern consistent with MikroTik-based botnet infrastructure."
---

## Overview

On April 2, 2026, my Cowrie SSH honeypot logged an unusual pattern — two
source IPs attempting to use the honeypot as a proxy to reach `ip-who.com`,
a service that returns the caller's external IP address in JSON format.
This is not attack behavior. This is **operational security behavior** — a
compromised node checking what IP address it appears to be using.

Investigation revealed both IPs are **compromised MikroTik routers** on
Vietnamese residential ISP infrastructure. A third IP from the same session
window — a Dutch scanner with 116,618 AbuseIPDB reports — attempted to tunnel
to Cloudflare's TURN server infrastructure, suggesting a separate actor testing
WebRTC-based connectivity through the honeypot.

---

## The Tunnel Attempts

Cowrie's `direct-tcpip` logging captured three actors attempting to use the
honeypot as a network relay on the same day. The raw requests tell the story:

**Vietnamese nodes — IP self-lookup:**
```
GET /json/ HTTP/1.1
Host: ip-who.com
```

Both `171.231.198.144` and `116.110.10.233` sent identical requests through
the tunnel to `ip-who.com/json/` — a free API that returns the caller's
external IP, ASN, and geolocation. Both requests carried the same JA4H
fingerprint (`ge11nn010000_4740ae6347b0`), confirming the same tool is behind
both source IPs.

**Dutch scanner — TURN connectivity test:**
```
GET / HTTP/1.1
Host: turn.cloudflare.com:3478
Connection: close
```

`45.148.10.121` attempted to reach Cloudflare's TURN server on port 3478 —
a STUN/TURN protocol port used for WebRTC NAT traversal. JA4H fingerprint:
`ge11nn020000_8d35d308f07e`. This suggests testing whether the honeypot could
serve as a relay node for WebRTC-based communication, potentially a C2
channel operating over standard WebRTC infrastructure to blend in with
legitimate video/voice traffic.

---

## The Vietnamese IPs — Compromised MikroTik Routers

### 171.231.198.144

| Property | Value |
|---|---|
| **ISP** | Viettel Group |
| **ASN** | AS7552 |
| **Location** | Qui Nhon, Gia Lai, Vietnam |
| **Usage type** | Fixed Line ISP |
| **AbuseIPDB reports** | 981 at 100% confidence |
| **Hostname** | dynamic-ip-adsl.viettel.vn |

Shodan and Censys both confirm this is a **MikroTik RouterOS 7.18.2** device
with two exposed services:

- **Port 2000** — MikroTik Bandwidth Test Server
- **Port 8291** — MikroTik Winbox

This is a residential ADSL router — the dynamic IP hostname confirms it.
MikroTik's Winbox protocol on port 8291 has been repeatedly exploited by
botnet operators to gain persistent access to routers, most notably by the
Mēris botnet campaign documented in 2021. The device is almost certainly
compromised and being used as a proxy node in a larger operation.

### 116.110.10.233

| Property | Value |
|---|---|
| **ISP** | Viettel Group |
| **ASN** | AS24086 |
| **Location** | Da Nang, Vietnam |
| **Usage type** | Fixed Line ISP |
| **AbuseIPDB reports** | 272 at 100% confidence |

No publicly exposed services visible on Censys — either behind NAT or services
are filtered. Also a Viettel residential connection. Identical JA4H fingerprint
to the Qui Nhon router confirms the same tooling.

### Why an IP lookup?

When malware or a botnet controller lands on a new node, one of the first
things it does is verify its apparent external IP. This serves several purposes:

1. **Proxy verification** — confirming the traffic is actually routing through
   the compromised router and not leaking the operator's real IP
2. **Geolocation confirmation** — verifying the node appears to be in the
   expected country for operational purposes
3. **Deduplication** — some botnets track active nodes by external IP to avoid
   using the same apparent IP twice

The fact that two geographically distinct Vietnamese routers used identical
tooling to perform the same check through the same honeypot suggests they are
nodes in the same botnet infrastructure, being managed by a common controller.

---

## The Dutch Scanner — 45.148.10.121

| Property | Value |
|---|---|
| **ISP** | TECHOFF SRV LIMITED / DMZHOST |
| **ASN** | AS48090 |
| **Location** | Amsterdam/Lelystad, Netherlands |
| **AbuseIPDB reports** | **116,618 at 100% confidence** |
| **Shodan tag** | Scanner |
| **Open ports** | 22 (OpenSSH 10.0p2 Debian) |

116,618 AbuseIPDB reports is one of the highest counts observed across this
honeypot project. This is a dedicated scanning and attack node on a Dutch
hosting provider — TECHOFF SRV LIMITED operating under the DMZHOST brand,
a provider with a known permissive abuse policy.

The TURN tunnel attempt is behaviorally distinct from the Vietnamese proxy
checks. Port 3478 to `turn.cloudflare.com` suggests either:

- **WebRTC C2 testing** — probing whether a compromised host can relay
  WebRTC traffic through Cloudflare's TURN infrastructure, which would
  blend C2 communications into legitimate video/voice traffic and evade
  standard port-based filtering
- **Connectivity probing** — generically testing what outbound ports and
  protocols the honeypot can reach

WebRTC-based C2 is an emerging technique that uses the STUN/TURN protocol
stack to tunnel command and control traffic through infrastructure that most
organizations allow by default. The JA4H fingerprint captured here
(`ge11nn020000_8d35d308f07e`) provides a signature for detecting this
specific tool in other environments.

---

## MikroTik Botnet Context

MikroTik routers have been a major target for botnet operators for years.
The Mēris botnet, documented by Qrator Labs and Yandex in 2021, specifically
exploited MikroTik devices running vulnerable RouterOS versions to build one
of the largest DDoS botnets ever observed — peaking at over 21 million
requests per second.

Key vulnerabilities exploited include:

- **CVE-2018-14847** — Winbox authentication bypass, allows unauthenticated
  file read including credential databases
- **Exposed Winbox (port 8291)** — internet-exposed management interface
  with weak or default credentials

The device observed in this capture (`171.231.198.144`) is running
RouterOS 7.18.2 with Winbox exposed directly to the internet. Whether
the compromise occurred via CVE-2018-14847, credential brute force, or
another vector is unknown — but the device's presence in a botnet doing
proxy verification is consistent with the Mēris operational pattern.

---

## What This Looks Like End-to-End

The operator's likely workflow:

1. Compromise MikroTik routers via exposed Winbox or known CVEs
2. Configure the routers to forward traffic through SSH tunnels on
   compromised Linux servers
3. Use the tunnel to verify the router appears as the external IP
   (via ip-who.com) — confirming the proxy chain is working
4. Use the verified proxy chain for subsequent attack operations,
   appearing to originate from Vietnamese residential infrastructure

From a victim's perspective, attacks originating from this infrastructure
look like they're coming from Vietnamese home users — not from the
operator's actual location.

---

## Indicators of Compromise

**Vietnamese proxy nodes:**
- `171.231.198.144` — MikroTik RouterOS 7.18.2, Viettel AS7552, Qui Nhon VN
- `116.110.10.233` — Viettel AS24086, Da Nang VN
- JA4H fingerprint: `ge11nn010000_4740ae6347b0`
- Tunnel destination: `ip-who.com:80` — `GET /json/ HTTP/1.1`

**Dutch scanner:**
- `45.148.10.121` — TECHOFF SRV LIMITED, AS48090, Amsterdam NL
- JA4H fingerprint: `ge11nn020000_8d35d308f07e`
- Tunnel destination: `turn.cloudflare.com:3478` — STUN/TURN probe

---

## Defensive Recommendations

**MikroTik operators:**
- Disable Winbox (port 8291) internet exposure — management should only
  be accessible from trusted internal networks or VPN
- Update RouterOS to the latest stable version
- Check for unknown scheduled tasks, NAT rules, or SOCKS proxy
  configurations — common Mēris persistence mechanisms
- Review `/ip/socks` and `/ip/firewall/nat` for unauthorized rules

**Network defenders:**
- JA4H fingerprint `ge11nn010000_4740ae6347b0` identifies the ip-who.com
  proxy verification tool observed in this capture
- Monitor for outbound STUN/TURN traffic (port 3478 UDP/TCP) from
  unexpected hosts — may indicate WebRTC-based C2 activity

---

## References

- Qrator Labs: Mēris Botnet —
  https://qrator.net/en/blog/meris-botnet-climbing-to-the-record/
- CVE-2018-14847 — MikroTik RouterOS Winbox Authentication Bypass
- Shodan host data: `171.231.198.144` (MikroTik RouterOS 7.18.2)
- AbuseIPDB: `45.148.10.121` (116,618 reports)
