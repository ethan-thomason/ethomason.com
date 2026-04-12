---
title: "Fingerprinting Inductive Automation Ignition Gateways Across Version Families"
date: 2026-04-12
author: "Ethan Thomason"
tags: ["ignition", "scada", "ics-security", "metasploit", "fingerprinting"]
draft: false
---

## Introduction


Ignition by Inductive Automation is one of the most widely deployed SCADA platforms in
North American critical infrastructure — water treatment, manufacturing, food and
beverage, oil and gas, pharmaceutical. During a network assessment, identifying an
Ignition gateway and its version is often the first step toward understanding the
attack surface. It's also one of the easiest things to do, because Ignition has
historically exposed version and configuration data without any authentication.

This post documents the version fingerprinting endpoints across all major Ignition
releases and introduces a Metasploit module that handles the differences automatically.

---

## Version Scope

This research covers Ignition 7.9.x and later. Pre-7.9 versions exist but are
genuinely end-of-life and absent from modern deployments — if you encounter one
in the field, version staleness is the finding, not anything this scanner surfaces.

7.9.x is worth including because it was Ignition's long-term support release for
several years and still appears in older industrial environments that haven't
migrated. 8.0.x is covered by the existing Metasploit module
`exploit/multi/scada/inductive_ignition_rce` (CVE-2020-10644, CVE-2020-12004) —
this scanner doesn't duplicate that module's 8.0.x coverage, but does reference
its fingerprinting behavior for completeness.

The CVEs this scanner feeds into — CVE-2022-35869, CVE-2023-39475, CVE-2023-39476
— all have version boundaries within the 8.1.x series, which is where the bulk
of this research is focused.

---

## The Endpoints

Ignition's info endpoint has changed format and path three times across major versions.
If you're writing tooling that needs to work across a mixed environment, you need to
handle all of them.

### 7.9.x — `/main/system/gwinfo`

Tested against Ignition 7.9.21:

```
$ curl -s http://target:8088/main/system/gwinfo
Version=7.9.21;ContextStatus=RUNNING;OS=Linux;RedundancyStatus=Independent;...
```

Semicolon-delimited key=value pairs. No authentication required. Returns version, run
state, OS, and GAN redundancy role.

### 8.0.x — `/system/gwinfo`

Same key=value format as 7.9.x, different path. A direct request to `/system/gwinfo`
returns 200; the older `/main/system/gwinfo` path returns a 302 redirect. This
behavior is confirmed by the existing Metasploit module
`exploit/multi/scada/inductive_ignition_rce`, which uses this endpoint for version
detection prior to exploitation — the `version_get` method in that module documents
the redirect behavior explicitly. I haven't tested an 8.0.x instance directly, so
for 8.0.x fingerprinting and exploitation, refer to that module.

### 8.1.x — `/system/StatusPing`

Tested against Ignition 8.1.15 and 8.1.17. In 8.1.x, IA switched to a JSON response
on a new path:

```
$ curl -s http://target:8088/system/StatusPing
{"state":"RUNNING","version":"8.1.15","os":"Linux","role":"INDEPENDENT",...}
```

More structured, same information, unauthenticated.

### 8.3.x — `/system/gwinfo` (again)

Tested against Ignition 8.3.4. In 8.3.x, IA moved back to `/system/gwinfo` with the
key=value format, but with additional fields including `RuntimeVersion` (the bundled
JRE version) and `RequireSsl`:

```
$ curl -s http://target:8088/system/gwinfo
ContextStatus=RUNNING;PlatformName=Ignition-hostname;Version=8.3.4;OS=Linux;
RuntimeVersion=17.0.17;RedundancyStatus=Independent;RequireSsl=false;...
```

`/system/StatusPing` still exists in 8.3.x but returns only `{"state":"RUNNING"}` —
no version data. Don't rely on it for fingerprinting.

---

## What This Exposes

Version disclosure on its own is a low-severity finding, but in practice it's a force
multiplier. Knowing the exact Ignition version lets you immediately map against known
CVEs — there are a significant number of unauthenticated RCEs in the 8.1.x series
alone — before sending a single malicious packet.

The GAN redundancy role disclosure is more interesting. `RedundancyStatus` tells you
whether you're looking at a standalone gateway, a primary (master), or a backup node.
`RedundantBackupAddresses` on a primary tells you the IP of the backup gateway. That's
free network topology — two nodes identified from a single unauthenticated request.

`RequireSsl=false` on 8.3.x gateways tells you the GAN channel is running in plaintext
mode, which is relevant for certain attack chains.

---

## Metasploit Module

I've written an auxiliary scanner module for Metasploit that handles all supported
version families automatically. It probes `/system/gwinfo`, `/system/StatusPing`, and
`/main/system/gwinfo` in sequence, parses both key=value and JSON response formats,
and reports findings to the MSF database.

```
msf6 > use auxiliary/scanner/scada/ignition_statusping
msf6 > set RHOSTS 10.10.0.0/24
msf6 > run

[+] 10.10.0.3:8088 - Ignition 8.3.4 | State: RUNNING | OS: Linux | Java: 17.0.17 | GAN role: Master
[+] 10.10.0.4:8088 - Ignition 8.3.4 | State: RUNNING | OS: Linux | Java: 17.0.17 | GAN role: Backup
[+] 10.10.0.7:8088 - Ignition 7.9.21 | State: RUNNING | OS: Linux | GAN role: Independent
[+] 10.10.0.8:8088 - Ignition 8.1.15 | State: RUNNING | OS: Linux | Java: 11.0.14.1 | GAN role: Independent
```

CIDR range scanning is handled automatically by the Scanner mixin — set `RHOSTS` to
a subnet and it sweeps the whole range. The module has been personally tested against
Ignition 7.9.21, 8.1.15, 8.1.17, and 8.3.4 on Linux. 8.0.x behavior is inferred
from the existing `inductive_ignition_rce` module source.

The module is pending submission to the Metasploit Framework. Source is available in
the meantime on GitHub at `github.com/ethan-thomason/metasploit-framework`.

---

## Remediation

The straightforward fix is network segmentation — port 8088 should not be reachable
from anything that isn't an engineering workstation or a known integration host.
Ignition's built-in firewall settings can restrict access at the application layer, but
network-level controls are more reliable.

For deployments where 8088 must be accessible on a broader network segment, enabling
SSL (`RequireSsl=true`) doesn't fix the information disclosure on `gwinfo` itself but
does add transport security to the rest of the gateway communication.

This is part of ongoing research into the Inductive Automation Ignition platform and
its ecosystem. More to follow.

---


*Ethan Thomason is the founder of [CedarTech](http://cedartech.com), a systems integration company specializing in OT/ICS environments. He is based in Northern California and writes about OT security at [ethomason.com](https://ethomason.com).*
