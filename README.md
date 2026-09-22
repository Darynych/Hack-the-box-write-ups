# HackTheBox Write-ups

Walkthroughs of **retired** HackTheBox machines by **Darina Askarova** (HTB handle: **Dragon**).

Each write-up documents a full assessment — reconnaissance, exploitation, lateral movement, and
privilege escalation — with evidence screenshots, a findings-and-remediation table, and the
defensive takeaways. Flag values and recovered secrets are **redacted** throughout, in line with
HackTheBox's policy.

---

## Machines

| Machine | OS | Difficulty | Outcome | Key vulnerability |
|---------|----|-----------|---------|-------------------|
| [DevHub](./devhub/) | Linux (Ubuntu 22.04) | Medium | User + Root | CVE-2026-23744 — MCPJam Inspector unauthenticated RCE |

*More machines will be added here as they retire.*

---

## Skills demonstrated

- Service enumeration and CVE research
- Web / API exploitation (unauthenticated RCE)
- Local enumeration and secret recovery
- Pivoting and SSH tunnelling to reach internal services
- Linux privilege escalation via over-privileged services
- Clear, evidence-backed reporting with mapped remediation

## Toolkit

`Kali / Arch Linux` · `Nmap` · `Ncat` · `curl` · `SSH` · `Jupyter` · Python

---

## ⚠️ Disclaimer & ethics

All machines were attacked in the **authorized HackTheBox lab environment**, for training and
educational purposes only. Write-ups are published **only after a machine has retired**, and all
flag values and recovered secrets (SSH keys, tokens, API keys) are redacted, in line with
HackTheBox's content policy.

---

## Connect

- **GitHub:** [@Darynych](https://github.com/Darynych)
- **HTB:** Dragon
- **LinkedIn:** _add your profile link here_
