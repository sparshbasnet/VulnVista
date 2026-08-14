# Running Metasploitable2 for VulnVista

> [!CAUTION]
> Metasploitable2 is intentionally riddled with vulnerabilities, including remote root
> access. Never expose it to any network beyond your isolated lab.

## Docker (default — uniform with the rest of the lab)

Rapid7 only distributes Metasploitable2 officially as a VMware/VirtualBox disk image —
there is no *official* Docker image. For local development and this project's Docker
Compose-based lab, we use [`tleemcjr/metasploitable2`](https://hub.docker.com/r/tleemcjr/metasploitable2)
(100K+ pulls), a community repackaging of the same rootfs the official VM ships. It's
wired into [`lab/docker-compose.yml`](./docker-compose.yml) alongside DVWA and Juice
Shop, so all three lab targets start and stop the same way:

```bash
docker compose --env-file .env -f lab/docker-compose.yml up -d
```

The container runs the image's own `/bin/services.sh` boot script to start the
vulnerable services (this happens automatically via the compose file's `command`) —
it's not a plain "run the image" situation like DVWA/Juice Shop. Default login for any
service requiring auth is `msfadmin` / `msfadmin`.

Two services **don't** come up under Docker and that's expected, not a bug: **bind9**
(DNS) and **NFS** both need kernel modules the container can't load. Every other
classic Metasploitable2 service (ftp, ssh, telnet, smtp, samba, mysql, postgresql,
distccd, the ingreslock/vsftpd/UnrealIRCd backdoors, tomcat, etc.) runs normally.

**Reachability:**

- From the backend container (i.e. what detectors use): `metasploitable2:<real-port>`
  on `vulnvista_net` — e.g. `metasploitable2:21` for FTP. Host port publishing below
  doesn't affect this.
- From the Docker host (for manual poking — `nmap`, `curl`, `nc`, etc.): each service's
  host port is its real port **+10000** (chosen purely to dodge collisions with
  anything already running on the host — 22, 3306, and 5432 in particular are common).
  So SSH is `localhost:10022`, MySQL is `localhost:13306`, PostgreSQL is
  `localhost:15432`, and so on — see the full mapping and what each port is in
  [`docker-compose.yml`](./docker-compose.yml)'s `metasploitable2` service.

Register it as a `Target` with `target_type: metasploitable2` and `base_url` pointed
at whichever service/port you're scanning (the detector will need per-service
handling since, unlike a single web app, this target exposes many independent
services rather than one HTTP surface).

## VM (higher-fidelity alternative)

If you want the exact, official Rapid7 image instead of a community Docker
repackaging — e.g. for a graded deliverable where fidelity to the real target
matters, or if the Docker image's missing bind9/NFS services matter for your
detector — run it as a VM instead.

### 1. Download

Get the official image from Rapid7's SourceForge listing:
<https://sourceforge.net/projects/metasploitable/files/Metasploitable2/>

It ships as a zipped VMware disk (`.vmdk`) — this also imports cleanly into
VirtualBox.

### 2. Import

**VirtualBox:**

1. `File > New`, type "Linux", version "Ubuntu (64-bit)" (Metasploitable2 is Ubuntu 8.04-based).
2. When asked for a hard disk, choose "Use an existing virtual hard disk file" and
   point it at the extracted `Metasploitable.vmdk`.
3. Allocate 512 MB–1 GB RAM (it's a lightweight, dated image).

**VMware Workstation/Player:**

1. `File > Open`, select the extracted `Metasploitable.vmx` (or create a new VM
   pointing at the `.vmdk` if only the disk is provided).

### 3. Network configuration — making it reachable from VulnVista

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

### 4. Boot and verify

1. Start the VM. Default login is `msfadmin` / `msfadmin`.
2. Run `ifconfig` inside the VM to confirm its IP address.
3. From the Docker host, confirm reachability: `nmap -sV <metasploitable-ip>` should
   show the expected vulnerable services (FTP, SSH, Telnet, SMB, MySQL, etc.).
4. Register that IP as a `Target` in VulnVista (`target_type: metasploitable2`,
   `is_allowed: true`) once you're ready to scan it.
