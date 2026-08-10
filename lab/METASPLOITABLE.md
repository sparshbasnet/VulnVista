# Running Metasploitable2 for VulnVista

Metasploitable2 is **not** run via Docker Compose in this project. Rapid7 only
distributes it as a VMware/VirtualBox disk image — there is no official Docker image,
and community Docker ports of it are unofficial repackagings of a deliberately
insecure multi-service Linux box, not something to trust or depend on for a graded
project. Run it as a VM instead.

> [!CAUTION]
> Metasploitable2 is intentionally riddled with vulnerabilities, including remote root
> access. Never expose it to any network beyond your isolated lab.

## 1. Download

Get the official image from Rapid7's SourceForge listing:
<https://sourceforge.net/projects/metasploitable/files/Metasploitable2/>

It ships as a zipped VMware disk (`.vmdk`) — this also imports cleanly into
VirtualBox.

## 2. Import

**VirtualBox:**

1. `File > New`, type "Linux", version "Ubuntu (64-bit)" (Metasploitable2 is Ubuntu 8.04-based).
2. When asked for a hard disk, choose "Use an existing virtual hard disk file" and
   point it at the extracted `Metasploitable.vmdk`.
3. Allocate 512 MB–1 GB RAM (it's a lightweight, dated image).

**VMware Workstation/Player:**

1. `File > Open`, select the extracted `Metasploitable.vmx` (or create a new VM
   pointing at the `.vmdk` if only the disk is provided).

## 3. Network configuration — making it reachable from VulnVista

The backend container talks to lab targets over the `vulnvista_net` Docker network
(a bridge network on the Docker host), so a VM needs a network path into that bridge:

- **Simplest for local development:** set the VM's network adapter to **Bridged**,
  attached to the same physical/host interface Docker's bridge routes through. This
  puts the VM on your LAN with its own IP — reachable from the Docker host (and thus
  from containers, if the host's Docker bridge can route to the LAN).
- **More isolated:** create a VirtualBox/VMware **Host-only** network and put both
  Metasploitable2 and nothing else sensitive on it, then reach it from the Docker
  host via that host-only interface. Register the VM's IP as its `base_url`/
  `ip_address` when you add it as a `Target` — the plan's target model supports an
  `ip_address` field for exactly this case.
- Either way: **do not** attach it to a network segment shared with anything else on
  your machine or LAN that isn't part of this lab.

## 4. Boot and verify

1. Start the VM. Default login is `msfadmin` / `msfadmin`.
2. Run `ifconfig` inside the VM to confirm its IP address.
3. From the Docker host, confirm reachability: `nmap -sV <metasploitable-ip>` should
   show the expected vulnerable services (FTP, SSH, Telnet, SMB, MySQL, etc.).
4. Register that IP as a `Target` in VulnVista (`target_type` e.g. `metasploitable2`,
   `is_allowed: true`) once you're ready to scan it.

## Unofficial alternative (use at your own risk)

Community-maintained Docker images of Metasploitable2 exist (e.g. searchable on
Docker Hub), but they are unofficial repackagings with no guarantee of fidelity to
the real target, and some have been abandoned or altered. If you use one anyway,
treat it exactly like the VM: isolate it on `vulnvista_net` (or a network reachable
from it) and never expose it beyond the lab.
