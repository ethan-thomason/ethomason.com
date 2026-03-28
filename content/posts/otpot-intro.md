---
title: "Introducing otpot: A Modern OT/ICS Honeypot (And What We Caught in the First 90 Minutes)"
date: 2026-03-28
author: "Ethan Thomason"
tags: ["honeypot", "otpot"]
draft: false
---

## First, Some Context: What Is a Honeypot and Why Does It Matter?

If you've spent your career on the OT side — programming PLCs, commissioning HMIs, integrating SCADA systems — cybersecurity might feel like someone else's department. That's changing fast, and if you're reading this, you probably already know it.

Here's the simplest way I can explain a honeypot: it's a trap.

You set up a system that looks exactly like something an attacker would want to find — an exposed PLC, an unprotected SCADA gateway, an industrial device sitting on the internet. But it's fake. Nothing real is connected to it. When an attacker finds it and starts probing, you're watching everything they do.

This serves two purposes. First, it gives you intelligence — you learn what tools attackers are using, what protocols they're targeting, what they're looking for when they scan for industrial systems. Second, it's a canary — if something hits your honeypot that looks like a targeted, human-driven attack rather than automated scanning, that's a signal worth paying attention to.

For OT environments specifically, this matters more than people realize. Industrial protocols like Modbus, EtherNet/IP, and S7Comm were designed for reliability and determinism inside trusted networks — security features were an afterthought, and in practice are rarely enabled even when available. But more and more of those factory networks have internet connectivity, either intentionally or accidentally. Attackers know this. They actively scan for exposed industrial devices.

A honeypot lets you see that activity — understand it, document it, and use it to make better security decisions.

That's what I built. Here's how it went.

---

## The Problem With Existing OT Honeypots

If you go looking for a dedicated open source OT honeypot today, the options are thin. The Honeynet Project lists two — conpot and riotpot — and both are marked as inactive.

Conpot, the more widely known of the two, sees occasional maintenance patches but is no longer under active development — the last substantive feature work was around 2020. It breaks on Python 3.11 and above due to unmaintained dependencies, requiring Python 3.10 or earlier to run at all. It also requires undocumented flags just to start, and has a fingerprinting vulnerability that makes it trivially identifiable to anyone who knows what they're looking for. riotpot was a Google Summer of Code project that went quiet after the funding ended.

There are general-purpose honeypots with some OT protocol support — OpenCanary from Thinkst is excellent and actively maintained — but nothing purpose-built for ICS/OT that is still being developed. That gap matters. Industrial environments are increasingly targeted, and the research community needs better tooling for capturing and understanding that threat activity.

So I forked conpot.

---

## Introducing otpot

[otpot](https://github.com/ethan-thomason/otpot) is an actively maintained fork of conpot, modernized for Python 3.10 and extended with fixes that should have been merged years ago.

I came to this project from an unusual angle. I've spent a decade working with industrial control systems — first at a systems integrator, then a vendor, and finally my own integration company. I know OT environments from the inside. I know what a real PLC looks like on the network, what a real HMI exposes, and what industrial protocol traffic looks like to a scanner.

That domain knowledge is the foundation of what I'm building.

---

## What Was Broken (And How I Fixed It)

Getting conpot running on a modern system is an adventure. After working through Python version conflicts, missing build dependencies, and undocumented runtime flags, I had it running — and immediately started finding bugs.

**The startup experience was broken.** Running conpot with a default configuration required passing an undocumented `--force` flag, or it would refuse to start with a cryptic error. A separate `-f` flag was required to bind to non-local interfaces — but `-f` was aliased to `--force`, creating a confusing situation where the two flags conflicted. These are now fixed. otpot starts with a single command:

```
conpot --template default --config conpot/testing.cfg
```

No flags. No workarounds.

**The HTTP service was leaking internal template syntax.** This is the most significant bug — and the most dangerous from a threat intelligence perspective. When you curl the HTTP port on a stock conpot instance, the response looks like this:

```
<TITLE>Overview - <condata source="databus" key="SystemDescription" /></TITLE>
```

That raw `<condata>` tag is conpot's internal template syntax. No real Siemens device would ever return it. Any scanner performing HTTP fingerprinting — human or automated — would immediately identify the host as a honeypot.

The root cause was subtle: Python's HTMLParser treats `<TITLE>` as a raw text element and doesn't parse child tags inside it. The original TemplateParser class relied on a handler that never fires for tags inside `<TITLE>`. The fix was to replace the HTMLParser-based approach with regex substitution that scans the full payload regardless of HTML context.

After the fix:

```
<TITLE>Overview - Siemens, SIMATIC, S7-200</TITLE>
```

A rendered, realistic device description. No internal syntax exposed.

---

## Deploying to Production

With the bugs fixed, I deployed otpot to a DigitalOcean VPS in San Francisco, running as a systemd service under a dedicated non-root user. I pointed a DNS record — `plc01.cedartech.com` — at the IP to make it look more like real OT infrastructure.

A bare IP address looks like a fresh VPS. A corporate hostname like `plc01.cedartech.com` looks like someone's production PLC sitting exposed on the internet. That's exactly the kind of misconfiguration attackers hunt for.

The honeypot was live at **22:17 UTC on March 27, 2026.**

otpot emulates the following protocols out of the box:

| Protocol | Purpose |
|----------|---------|
| Modbus TCP | Dominant PLC communication protocol |
| S7Comm | Siemens PLC protocol |
| EtherNet/IP | Rockwell/Allen-Bradley PLC protocol |
| BACnet | Building automation |
| SNMP | Network device management |
| HTTP | Web-based HMI interface |
| FTP | File transfer |
| TFTP | Trivial file transfer |
| IPMI | Server management |

---

## What Happened in the First 90 Minutes

**22:21 UTC — First web scanner**

Within four minutes of going live, HTTP scanners from `195.184.76.x` were probing port 8800. They sent Firefox user agents, requested `/` and `/favicon.ico`, and got a 302 redirect and a 404 respectively. Classic web fingerprinting behavior — automated tools checking what kind of web interface is running.

**00:21 UTC — More HTTP probes**

A scanner from `91.230.168.x` hit `/favicon.ico` and `/index.html`. They got a 200 on index.html — the first external entity to receive our rendered Siemens S7-200 page with the HTTP fix working correctly in production.

**00:54 UTC — The interesting one**

A connection from `66.132.172.98` hit port 44818 — the EtherNet/IP port. This wasn't an HTTP probe. This was a full CIP protocol enumeration. CIP (Common Industrial Protocol) is the application layer protocol that runs over EtherNet/IP — it's what you use to actually talk to Allen-Bradley PLCs.

The sequence:

1. **List Identity request** — "Who are you?"
2. Response: `1756-L61/B LOGIX5561` — an Allen-Bradley ControlLogix PLC, Vendor ID 1, Device Type 14, Serial Number 7079450
3. **List Services request** — "What can you do?"
4. Response: `Communications` service
5. Clean disconnect

The sender context bytes in the request decoded to `OISYSNEC` — the fingerprint of the Censys internet scanner. Censys is one of the two largest internet scanning platforms in the world, alongside Shodan. They continuously scan the entire internet and index what they find.

Within 31 minutes of that probe, my IP appeared in the Censys database indexed as:

- **Vendor:** Rockwell Automation/Allen-Bradley
- **Product:** 1756-L61/B LOGIX5561
- **Type:** Programmable Logic Controller
- **Serial Number:** 7079450

And tagged: **HONEYPOT** | **ICS**

---

## How Censys Detected Us

Censys correctly identified otpot as a Conpot honeypot. Here's how I believe they did it.

**The serial number.** Serial number `7079450` is hardcoded in conpot's default EtherNet/IP template. Every conpot instance in the world advertises the same serial number. Censys almost certainly has this value in their honeypot fingerprint database — it's a trivial, static signature. This is the equivalent of every fake ID in the world having the same birthday.

**Cross-protocol inconsistency.** The HTTP service presents as a Siemens S7-200 (German industrial manufacturer), while the EtherNet/IP service presents as an Allen-Bradley ControlLogix (American industrial manufacturer). No real device is both simultaneously. Censys correlates data across protocols and this inconsistency is an immediate red flag.

**Known conpot response patterns.** Beyond the serial number, specific field combinations in the CIP identity response may also match known conpot signatures.

Getting caught this fast is actually the most valuable finding of the weekend. It tells me exactly what to fix.

---

## What This Means for Real OT Environments

Here's the takeaway for anyone running OT infrastructure:

**Censys found a simulated PLC in under 31 minutes.** They would find a real one just as fast. If you have any industrial device with a routable IP address — even behind NAT with port forwarding — there is a meaningful chance it is already indexed by Censys, Shodan, or both.

These platforms are used by security researchers, but they're also used by threat actors looking for targets. An exposed Modbus device, an unprotected EtherNet/IP endpoint, an HMI with a web interface — these show up in search results just like websites do.

The good news: if you know your devices are indexed, you can monitor what's being captured. That's exactly what a honeypot helps you do in a controlled way.

---

## What's Next for otpot

The immediate priority is defeating the Censys detection. The serial number fix is straightforward — generate a random value at startup so no two otpot instances share the same fingerprint. The cross-protocol consistency fix is more involved — the device needs to present a coherent identity across all protocols.

Beyond fingerprinting, the roadmap includes Python 3.11 support, a REST API for runtime management, container-native deployment, and new protocol templates targeting modern ICS environments. The goal is to make otpot the de facto open source OT honeypot — something that's actually hard to fingerprint, easy to deploy, and generates real, actionable threat intelligence.

If you're in the OT/ICS space and this interests you — as a researcher, as a practitioner, or just as someone who's curious about what's actually scanning for industrial systems on the internet — the project is open source and contributions are welcome.

**GitHub:** [github.com/ethan-thomason/otpot](https://github.com/ethan-thomason/otpot)

The data is already coming in. More to follow.

---

*Ethan Thomason is the founder of [CedarTech](http://cedartech.com), a systems integration company specializing in OT/ICS environments. He is based in Northern California and writes about OT security at [ethomason.com](https://ethomason.com).*
