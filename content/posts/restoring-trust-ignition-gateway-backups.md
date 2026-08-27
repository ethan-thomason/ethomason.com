---
title: "Restoring Trust: A Code-Execution Story in Ignition Gateway Backups"
date: 2026-08-27
draft: false
tags: ["ICS", "SCADA", "Ignition", "CVE", "disclosure"]
---

# Restoring Trust: A Code-Execution Story in Ignition Gateway Backups

I spend most of my time inside Inductive Automation's Ignition platform. Years of integration work will do that — you get to know a system's habits, the places it trusts input a little too readily, the seams where convenience and security pull in opposite directions. Lately I've been pointing that familiarity in a different direction: instead of building on Ignition, I've been probing it. This is the story of one of those probes, and of a disclosure process that worked the way it's supposed to.

## Where the idea came from

This one started with Meterpreter. I was working through Metasploit's payload delivery — the mechanics of getting code onto a target and calling home — and somewhere in that the question flipped around on me: how *would* you deliver a payload to an Ignition box? Not as an abstract exercise, but concretely, using the machinery Ignition already hands you.

The answer was sitting in plain sight. Gateway backups restore trusted project resources — including scripts. Those scripts run in the gateway's own context. And the gateway runs as a service account that, on a default install, is badly over-privileged. So the delivery mechanism wasn't some exotic exploit primitive; it was the backup/restore feature working exactly as designed. Trusted content in, code execution out. Once I saw it that way, I had to go confirm it in the lab.

## The finding

Ignition gateways can be backed up and restored through a single file — a `.gwbk` gateway backup. It's a routine operation. Migrate a gateway to new hardware, stand up a redundant backup node, snapshot a gateway before an upgrade, or hand a full gateway to support for troubleshooting, and you're moving `.gwbk` files. The restore is a trusted operation performed by trusted people.

That trust is the interesting part. A gateway backup can carry project resources, scripts, and modules. When an authenticated administrator restores a crafted backup, that content is loaded into the gateway — and the gateway runs as a service account on the host operating system. The result is code execution on the host, in the context of whatever account runs the Ignition service.

On a default installation, that account is frequently far more privileged than it needs to be. On Windows, Ignition often runs as `NT AUTHORITY\SYSTEM`. On Linux — the environment I work in most — default deployment paths commonly leave the service running as root or with elevated privileges unless an operator has gone out of their way to lock it down. So the blast radius of "an administrator restored a backup" can be "code execution with full system privileges."

I want to be precise about what this is and isn't. It requires an authenticated user with Gateway Administrator rights. It isn't a remote, unauthenticated break-in. But administrator-restores-a-backup is a *normal* operation, and the gap between "intended function" and "unintended blast radius" is exactly the kind of thing worth surfacing — because the fix isn't obvious to the operator who's just doing their job.

## The part I didn't know

Here's the honest version of how this went, because I think the honesty is the point.

I found this independently. I was working on Linux, testing the restore path, and I watched it execute code as an over-privileged service account. From where I sat, it was a discovery — I had no idea anyone had looked at this before. I wrote it up, validated it in my lab, and reported it.

It was only through the disclosure process that I learned the vulnerability had already been reported — by Momen Eldawakhly of Samurai Digital Security — and published months earlier as CVE-2025-13911 and [ICSA-25-352-01](https://www.cisa.gov/news-events/ics-advisories/icsa-25-352-01). Their original research was Windows-focused. Mine was Linux, found cold, with no knowledge of theirs.

Two researchers arriving at the same door from different rooms isn't a failure of originality. It's confirmation the door is real. And it turned out the independent Linux angle mattered, because the published advisory and CVE were framed almost entirely around Windows and SYSTEM-level execution. The cross-platform reality — that a default Linux install is equally exposed, often as root — wasn't reflected in the official language. That inconsistency, between the documented scope and the actual exposure, is what my research surfaced.

## The disclosure

This is the part I most want to talk about, because coordinated disclosure gets a bad reputation it doesn't always deserve.

I reported to Inductive Automation. They reviewed the full submission, agreed the Linux exposure was real and under-represented, and moved to correct the advisory to reflect cross-platform impact. When I raised concerns about specific language, they held a scheduled release date to incorporate my input and coordinated with CISA to get me properly credited. My findings around the platform differences — default service-account behavior, the privilege model, the post-exploitation surface — are reflected in the updated advisory.

We didn't agree on everything, and that's fine. We had a substantive back-and-forth about whether the Linux surface warranted a separate CVE or an amendment to the existing one. I made my case; they made theirs — same root cause, same vector, same privilege requirement, so an amendment rather than a new CVE. They were right, and I said so. That's what good coordination looks like: two parties who both want the record to be accurate, working it out.

The [updated advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-25-352-01) (ICSA-25-352-01, Update A) credits both Momen Eldawakhly of Samurai Digital Security and me. I independently discovered this class of issue on Linux, unaware it had been reported on Windows, and my work led to the advisory reflecting cross-platform impact.

## Why this matters beyond one CVE

The technical lesson is small and old: services should run with the least privilege they need, and "the product executes code by design" is not a reason to hand that execution SYSTEM or root. Ignition's own hardening guidance covers this, and the vendor is developing application-level controls on top of it. If you run Ignition, the single highest-value thing you can do is run the service under a dedicated, minimally-privileged account rather than the default. That one change shrinks the blast radius of a whole category of issues, not just this one.

The broader lesson is about the disclosure ecosystem. Independent rediscovery happens. Advisories get scoped too narrowly the first time. The system works when researchers report in good faith and vendors respond in good faith — and in this case, both did.

I've built my reputation on knowing Ignition deeply. Increasingly, I'm using that depth to make the platform and the ecosystem around it more secure. This is one piece of that work, and there's more coming.

---

*Ethan Thomason is the founder of CedarTech, where he works on ICS/SCADA integration and security research with a focus on the Inductive Automation Ignition ecosystem. More research at ethomason.com.*
