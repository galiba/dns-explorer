# DNS Explorer

A dnsdumpster-style DNS recon tool with a web UI. Point it at a domain and it
maps the zone using techniques that surface *real* hosts — no subdomain
wordlist brute-force (which wildcard DNS defeats anyway).

## Discovery techniques
1. **Zone transfer (AXFR)** — asks the domain's nameservers (or a custom
   internal NS you supply) to dump every record they hold: A, AAAA, CNAME, MX,
   TXT, SRV, NS, PTR, etc. The right way to enumerate an internal DNS server.
2. **Direct apex queries** — if AXFR is refused, queries the apex directly for
   SOA/NS/A/AAAA/MX/TXT/CNAME/SRV/CAA.
3. **Passive discovery** — pulls already-indexed subdomains from certificate
   transparency / public sources, then resolves each against your chosen
   resolver to confirm it's live. All sources are queried concurrently and the
   results **unioned** — each finds names the others miss:
   - **crt.sh** (Sectigo CT search)
   - **Cert Spotter / SSLMate** (`api.certspotter.com`)
   - **CertKit** (`ct.certkit.io`)
   - **HackerTarget** (`api.hackertarget.com`, DNS host dataset)

Every A/AAAA host is enriched with reverse DNS (PTR), ASN / netblock owner
(Team Cymru, no API key), and optional HTTP/HTTPS `Server` banners. The graph
extends each IP to its reverse-DNS node, which often reveals the CDN /
reverse proxy fronting it (e.g. `*.cloudfront.net`, `*.1e100.net`). A **Source**
column tags each row (AXFR / apex / passive). Wildcard DNS is auto-detected and
flagged so bogus resolutions are obvious. One-click **.xlsx export**.

## Run
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
```
Open http://localhost:8000

Binding to `127.0.0.1` keeps the server on loopback only (not exposed to your
network, and avoids the macOS firewall prompt for the listening socket).

## Internal nameservers & split-horizon
Put your internal DNS server IP(s) in the **Nameserver** field
(e.g. `10.0.0.53`, space/comma separated for several). It's used as the AXFR
target and resolver. Leave blank to use the system resolver.

When an internal NS is set, the tool **also queries a public resolver**
(1.1.1.1 / 8.8.8.8) and unions the answers — so a split-horizon host shows
*both* its internal record and its public record. The **View** column tags each
row `internal`, `external`, or `both`, and **Scope** flags each IP
`internal` (RFC1918/loopback/ULA) or `public`. ASN/PTR lookups route
internal IPs through the internal NS and public IPs through system DNS.

## Notes
- AXFR against most public domains is refused (by design) — it shines against
  internal/misconfigured nameservers. `zonetransfer.me` is a public test zone.
- Passive sources are best-effort and rate-limited; results vary by domain.
- Only scan domains/nameservers you're authorized to test.
