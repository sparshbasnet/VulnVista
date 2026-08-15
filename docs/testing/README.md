# Testing Guide

This folder documents the lab applications used for VulnVista testing, which browser URLs to open for each one, and a simple way to verify that everything is running.

## What is in the lab

| App                | Purpose                         | Browser URL                                                       |
| ------------------ | ------------------------------- | ----------------------------------------------------------------- |
| VulnVista frontend | Main dashboard UI               | http://localhost:5173                                             |
| VulnVista backend  | API and scan engine             | http://localhost:9000/api/health                                  |
| PostgreSQL         | Database backing the app        | Not opened in a browser; the default host port is 5432            |
| pgAdmin            | Optional database admin UI      | http://localhost:5050                                             |
| DVWA               | Deliberately vulnerable web app | http://localhost:8080                                            |
| OWASP Juice Shop   | Deliberately vulnerable web app | http://localhost:3000                                             |
| TLS test service   | Weak TLS test target            | https://localhost:8443                                            |
| Metasploitable2    | Multi-service vulnerable target | Browser access depends on the service; see the port mapping below |

## Port mapping

### Main application stack

| Service    | Host port | Notes                                             |
| ---------- | --------- | ------------------------------------------------- |
| Frontend   | 5173      | Opens the React dashboard in the browser          |
| Backend    | 9000      | Use the health endpoint in a browser: /api/health |
| PostgreSQL | 5432      | Used by the backend; not a browser target         |
| pgAdmin    | 5050      | Optional UI for checking database state           |

### Lab targets

| Service                              | Host port             | Notes                                                              |
| ------------------------------------ | --------------------- | ------------------------------------------------------------------ |
| DVWA                                 | 8080                  | Web app target for command injection and other browser-based tests |
| Juice Shop                           | 3000                  | Web app target for weak auth and sensitive-file checks             |
| TLS test service                     | 8443                  | Used for weak TLS testing                                          |
| Metasploitable2 FTP                  | 10021                 | Service exposed for service discovery tests                        |
| Metasploitable2 SSH                  | 10022                 | Service exposed for service discovery tests                        |
| Metasploitable2 Telnet               | 10023                 | Service exposed for service discovery tests                        |
| Metasploitable2 SMTP                 | 10025                 | Service exposed for service discovery tests                        |
| Metasploitable2 DNS                  | 10053                 | May not start fully in Docker                                      |
| Metasploitable2 HTTP                 | 10080                 | Web service target                                                 |
| Metasploitable2 RPCbind              | 10111                 | Service discovery target                                           |
| Metasploitable2 NetBIOS/SMB          | 10139 / 10445         | Service discovery target                                           |
| Metasploitable2 Rexec / Rlogin / Rsh | 10512 / 10513 / 10514 | Service discovery target                                           |
| Metasploitable2 Java RMI             | 11099                 | Service discovery target                                           |
| Metasploitable2 Ingreslock           | 11524                 | Backdoor service target                                            |
| Metasploitable2 NFS                  | 12049                 | May not start fully in Docker                                      |
| Metasploitable2 FTP (ProFTPD)        | 12121                 | Service discovery target                                           |
| Metasploitable2 MySQL                | 13306                 | Service discovery target                                           |
| Metasploitable2 distccd              | 13632                 | Service discovery target                                           |
| Metasploitable2 PostgreSQL           | 15432                 | Service discovery target                                           |
| Metasploitable2 VNC                  | 15900                 | Service discovery target                                           |
| Metasploitable2 X11                  | 16000                 | Service discovery target                                           |
| Metasploitable2 vsftpd backdoor      | 16200                 | Service discovery target                                           |
| Metasploitable2 IRC                  | 16667                 | Service discovery target                                           |
| Metasploitable2 AJP13                | 18009                 | Service discovery target                                           |
| Metasploitable2 Tomcat HTTP          | 18180                 | Service discovery target                                           |

## How to test each app

1. Start the main app stack with `docker compose up --build` from the repository root.
2. Start the lab targets with `docker compose --env-file .env -f lab/docker-compose.yml up -d`.
3. Open the frontend at http://localhost:5173 and confirm the dashboard loads.
4. Open the backend health endpoint at http://localhost:9000/api/health and confirm it returns a healthy response.
5. Open DVWA at http://localhost:8080 and log in with admin / password if needed.
6. Open Juice Shop at http://localhost:3000 and confirm the home page loads.
7. Open the TLS test service at https://localhost:8443 and accept the self-signed certificate warning.
8. For Metasploitable2, test a service port directly from the host, for example:

```bash
nmap -sV localhost -p10021,10022,10023,10080,13306,15432,18180
```

## Recommended test order

1. Check the backend health endpoint first.
2. Confirm the frontend loads.
3. Confirm each lab target opens at its expected port.
4. Run the scanner against the lab targets only.
5. Verify scan results appear in the dashboard after the scan completes.

## Notes

- The lab targets are intentionally vulnerable and must stay isolated.
- Metasploitable2 exposes many services, so service-level testing is more useful than a single browser page.
- If a port does not open, verify the corresponding container is running and that the shared `vulnvista_net` network was created by the setup script.
