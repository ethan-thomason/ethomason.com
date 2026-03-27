---
title: "Panchan Miner Delivered via Fake sshd Binary — Three-Year Campaign Still Active"
date: 2026-03-27
draft: false
tags: ["honeypot", "threat-intel", "panchan", "cryptominer", "cowrie", "linux-malware"]
description: "A 28.9MB Go-compiled ELF binary disguised as sshd was uploaded to my Cowrie honeypot via SFTP from a CHINANET IP. Sandbox analysis confirms Panchan miner — a peer-to-peer cryptominer active since at least June 2023 and still being deployed daily as of March 2026."
---

## Overview

Two days after my honeypot went live, a quieter and more patient actor arrived.
While the mdrfckr/Outlaw Group SSH key persistence campaign documented in my
[previous post](/posts/redtail-outlaw-turf-war/) continued running in the
background, this actor uploaded a malicious binary disguised as the system SSH
daemon — a stealth-focused approach targeting hosts they expect to have
long-term value.

Sandbox analysis and YARA matching confirm this is **Panchan** — a
peer-to-peer Go-compiled cryptominer with documented activity stretching back
to at least June 2023 and still being actively deployed as of this writing.

---

## The Capture

On 2026-03-27 at 00:16:09 UTC, Cowrie logged an SFTP file upload event from
`222.89.138.40`:
```
SFTP Uploaded file "sshd" to var/lib/cowrie/downloads/94f2e4d8...
```

The filename `sshd` is deliberate. On a real Linux system, the legitimate SSH
daemon lives at `/usr/sbin/sshd`. Replacing or supplementing it with a
malicious same-named binary allows the malware to persist invisibly — process
listings show `sshd` running, nothing looks wrong.

Cowrie captured the file before execution. On a real server, it would have run.

---

## Binary Analysis

| Property | Value |
|---|---|
| **Filename** | `sshd` |
| **SHA-256** | `94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00` |
| **File type** | ELF 64-bit LSB executable, x86-64 |
| **File size** | 28.90 MB (30,304,472 bytes) |
| **Compiler** | Go (AMD64) + gcc (Ubuntu 9.4.0) |
| **First submitted VT** | 2022-04-20 |
| **First seen in wild** | 2023-12-06 |
| **Last submission** | 2026-03-25 |
| **VT detections** | 45/65 |
| **Hybrid Analysis threat score** | 100/100 |
| **Label** | `Trojan.252279.Linux` |
| **Family** | Panchan miner |

### Panchan Attribution

Hybrid Analysis YARA matching confirmed **`Panchan miner`** — a peer-to-peer
Go-compiled SSH worm and cryptominer first documented by Akamai's Security
Intelligence Group in 2022. Panchan spreads by brute-forcing SSH credentials,
deploys miners, and uses a peer-to-peer architecture rather than traditional
C2 servers, making infrastructure takedowns significantly harder.

Key characteristics confirmed by static analysis:

- **Go-compiled, x86-64 only** — unlike Redtail which ships multi-architecture
  binaries, this targets x86-64 Linux servers exclusively
- **28.9MB statically linked** — all dependencies bundled for portable
  deployment
- **Binary stripped** — debug symbols removed to hinder analysis
- **PAM hooks** (`pam_acct_mgmt`, `pam_open_session`, `pam_get_item`) —
  the binary interfaces with Linux's Pluggable Authentication Modules,
  suggesting credential harvesting capability alongside mining
- **SFTP capability** (`*sftp.fx`) — built-in file transfer, consistent with
  the upload delivery method observed
- **AES/RSA encryption** — encrypted C2 communications
- **Multi-threaded** (`pthread_*`) — concurrent operations

The `@@@@@@` string patterns in the extracted strings are characteristic of
Panchan's peer list formatting, consistent with prior Akamai documentation.

### MITRE ATT&CK Techniques

| ID | Technique | Tactic |
|---|---|---|
| T1106 | Native API | Execution |
| T1204.002 | Malicious File | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1027.013 | Encrypted/Encoded File | Defense Evasion |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion |
| T1071 | Application Layer Protocol | Command and Control |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Exfiltration |

---

## Campaign Longevity

This is not a new or opportunistic deployment. VT submission history and
Hybrid Analysis reports show this exact binary has been submitted by Cowrie
honeypot operators on an almost daily basis since at least **March 15, 2026**,
with sandbox runs dating back to **June 2023**:
```
20260323-073452_sftp__root_sshd  ← 3 days before this capture
20260321-025628_sftp__root_sshd
20260320-163346_sftp__root_sshd
20260318-045718_sftp__root_sshd
20260317-185114_sftp__root_sshd
20260317-124954_sftp__root_sshd
20260317-050356_sftp__root_sshd
20260315-203124_sftp__root_sshd
20260315-170042_sftp__root_sshd
20260315-051458_sftp__root_sshd  ← earliest March capture
```

The filename pattern matches Cowrie's internal SFTP capture convention,
confirming these are all honeypot captures from other operators. This binary
has been hitting honeypots across the internet for at minimum the past two
weeks at near-daily frequency, and the same binary has been in circulation
since mid-2023.

Community analysis from the Louisiana Cyber Investigators Alliance (LCIA),
documented via VT community tab, captured this binary in February 2026 from
`51.89.255.72` (AS16276, UK) with the following execution pattern:
```bash
chmod +x ./.sshd
nohup ./.sshd [list of peer IPs]
```

The IP list passed as runtime arguments is consistent with Panchan's
peer-to-peer architecture — nodes in the peer list rather than traditional C2
infrastructure.

---

## Source IP

| Property | Value |
|---|---|
| **IP** | `222.89.138.40` |
| **ISP** | CHINANET Henan Province Network |
| **ASN** | AS4134 |
| **City** | Zhengzhou, Henan, China |
| **AbuseIPDB reports** | 5,092 |
| **Confidence of abuse** | 100% |

5,092 AbuseIPDB reports at 100% confidence. This is a heavily abused node
with a long history of malicious activity predating this capture.

---

## Comparison to Concurrent mdrfckr Campaign

Both campaigns were active on the same honeypot within the same 48-hour window:

| | mdrfckr / Outlaw Group | Panchan |
|---|---|---|
| **Technique** | SSH key persistence, credential spray | SFTP binary upload |
| **Goal** | Botnet expansion, mining staging | Cryptomining via P2P worm |
| **Tooling** | Go botnet, shell scripts | Go ELF, PAM hooks |
| **Source** | Distributed, rotating IPs | Single CHINANET IP |
| **Volume** | High — hundreds of sessions | Low — single upload attempt |
| **Stealth** | None — aggressive and loud | sshd impersonation, stripped binary |
| **Infrastructure** | Traditional C2 | Peer-to-peer, no central C2 |

The contrast is instructive. Outlaw Group is loud and fast — spray credentials,
install key, move on to the next host. Panchan is quieter — authenticate once,
upload a binary designed to look like a system process, mine indefinitely.

On a real production server, Panchan's approach is significantly harder to
detect without explicit binary integrity monitoring. The mdrfckr campaign would
trigger SSH alerts immediately. Panchan might run for weeks unnoticed.

---

## Defensive Recommendations

**Binary integrity monitoring** is the most effective control. Tools like
`aide`, `tripwire`, or auditd rules watching `/usr/sbin/sshd` for modification
will catch a replacement before it runs undetected.

**File size as an indicator** — legitimate `sshd` on Ubuntu 24.04 is
approximately 900KB. A 28.9MB binary named `sshd` is immediately anomalous
regardless of AV detection status.

**SFTP logging** — ensure your SSH configuration logs SFTP file transfers.
Many default configurations do not. Cowrie captured this because it logs
everything; a production server with default OpenSSH config might not.

---

## Indicators of Compromise

**Network:**
- `222.89.138.40` — upload source (CHINANET AS4134, Zhengzhou, China)
- `51.89.255.72` — alternate source documented by LCIA (AS16276, UK)

**File:**
- SHA-256: `94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00`
- MD5: `0fa41de75420479c9120641df3b4f317`
- SHA-1: `cbe89930c606fafad01189ce3dacc5228115bd4a`
- Related sample: `b7c9640040563749ddc8d6f0ee6078afe4f5ed15f941dbf2fd81e523cb47ef40`
- Filename: `sshd` (masquerading as SSH daemon)
- Size: 28.90 MB — legitimate sshd is ~900KB

**Detection names:**
- `Trojan.252279.Linux` (Hybrid Analysis / Falcon Sandbox)
- `trojan.multiverze/genericrxss` (VirusTotal popular label)
- `CoinMiner/Linux.Agent.30304472` (AhnLab)
- `Miner:Linux/CoinMiner.JUO` (AliCloud)
- YARA: `Panchan miner` (Hybrid Analysis)

---

## References

- Akamai: Panchan — A Peer-to-Peer Botnet and SSH Worm That Runs on Your
  Golang Projects —
  https://www.akamai.com/blog/security-research/panchan-golang-peer-to-peer-botnet
- Hybrid Analysis report (March 2026):
  https://hybrid-analysis.com (search SHA-256 above)
- LCIA community analysis: VT community tab for this sample
- AlienVault APT1 YARA ruleset:
  https://github.com/AlienVault-Labs/AlienVaultLabs
