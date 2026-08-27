"""DNS Explorer — dnsdumpster-style DNS recon over a chosen (public or internal) resolver.

Enumeration is done the right way: try a zone transfer (AXFR) against the domain's
nameservers (or a user-supplied internal NS) to dump every record it holds. No
subdomain wordlist — so wildcard DNS can't manufacture fake hosts. If AXFR is
refused, fall back to direct record-type queries on the apex.
"""
import io, ipaddress, secrets
from concurrent.futures import ThreadPoolExecutor

import dns.resolver, dns.reversename, dns.query, dns.zone, dns.rdatatype
import requests, urllib3
urllib3.disable_warnings()
from fastapi import FastAPI
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment

app = FastAPI(title="DNS Explorer")

APEX_TYPES = ("SOA", "NS", "A", "AAAA", "MX", "TXT", "CNAME", "SRV", "CAA")

_ASN_CACHE: dict[str, str] = {}


class Query(BaseModel):
    domain: str
    resolver: str | None = None   # custom (internal) nameserver IP(s); None = system
    grab_http: bool = True
    passive: bool = True    # crt.sh certificate-transparency discovery


def _split(s: str) -> list[str]:
    return [x.strip() for x in (s or "").replace(",", " ").split() if x.strip()]


def _resolver(ns: str | None) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=ns is None)
    if ns:
        r.nameservers = _split(ns)
    r.lifetime = r.timeout = 4.0
    return r


def _asn(ip: str) -> str:
    """Team Cymru DNS whois — free, no key. Skips private/IPv6; caches by /24."""
    try:
        if ":" in ip or ipaddress.ip_address(ip).is_private:
            return ""
        key = ip.rsplit(".", 1)[0]
        if key in _ASN_CACHE:
            return _ASN_CACHE[key]
        pub = dns.resolver.Resolver(configure=False)
        pub.nameservers = ["1.1.1.1", "8.8.8.8"]
        pub.lifetime = pub.timeout = 3.0
        rev = ".".join(reversed(ip.split(".")))
        r1 = pub.resolve(f"{rev}.origin.asn.cymru.com", "TXT")[0].to_text().strip('"')
        num, net = r1.split("|")[0].strip(), r1.split("|")[1].strip()
        name = pub.resolve(f"AS{num}.asn.cymru.com", "TXT")[0].to_text().strip('"')
        out = f"{name.split('|')[-1].strip()}\n{num} / {net}"
        _ASN_CACHE[key] = out
        return out
    except Exception:
        return ""


def _ptr(ip: str, ns: str | None) -> str:
    try:
        r = _resolver(ns)
        return str(r.resolve(dns.reversename.from_address(ip), "PTR")[0]).rstrip(".")
    except Exception:
        return ""


def _banner(host: str) -> str:
    out = []
    for scheme in ("http", "https"):
        try:
            r = requests.head(f"{scheme}://{host}", timeout=3, allow_redirects=False,
                              verify=False, headers={"User-Agent": "dns-explorer"})
            out.append(f"{scheme.upper()}: {r.headers.get('Server', 'unknown')} [{r.status_code}]")
        except Exception:
            pass
    return "\n".join(out)


def _enrich(row: dict, ns: str | None, grab_http: bool) -> dict:
    ip = row["value"]
    try:
        row["scope"] = "internal" if ipaddress.ip_address(ip).is_private else "public"
    except Exception:
        row["scope"] = ""
    row["reverse"] = _ptr(ip, ns)
    row["owner"] = _asn(ip)
    row["http"] = _banner(row["host"]) if grab_http else ""
    return row


def _axfr(domain: str, ns_ip: str) -> list[dict]:
    """Zone transfer against one nameserver IP. Returns [] on refusal/error."""
    rows = []
    z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=8.0))
    for name, node in z.nodes.items():
        fqdn = str(name.derelativize(z.origin)).rstrip(".")
        for rds in node.rdatasets:
            rtype = dns.rdatatype.to_text(rds.rdtype)
            for rd in rds:
                rows.append({"host": fqdn, "type": rtype, "value": rd.to_text(),
                             "reverse": "", "owner": "", "http": "", "source": "AXFR"})
    return rows


def _resolve_host(host: str, ns: str | None) -> list[dict]:
    """Resolve one host for A/AAAA/CNAME with its own resolver (thread-safe)."""
    out = []
    r = _resolver(ns)
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            for rec in r.resolve(host, rtype):
                val = rec.address if rtype != "CNAME" else str(rec.target).rstrip(".")
                out.append({"host": host, "type": rtype, "value": val,
                            "reverse": "", "owner": "", "http": "", "source": "passive"})
        except Exception:
            pass
    return out


_UA = {"User-Agent": "dns-explorer"}


def _clean(names, domain: str) -> set:
    out = set()
    for n in names:
        n = (n or "").strip().lstrip("*.").lower().rstrip(".")
        if n.endswith(domain) and " " not in n and "@" not in n:
            out.add(n)
    return out


def _src_crtsh(domain: str) -> set:
    r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15, headers=_UA)
    if not (r.ok and r.headers.get("content-type", "").startswith("application/json")):
        return set()
    out = set()
    for row in r.json():
        out |= _clean(row.get("name_value", "").splitlines(), domain)
    return out


def _src_certspotter(domain: str) -> set:
    r = requests.get(f"https://api.certspotter.com/v1/issuances?domain={domain}"
                     "&include_subdomains=true&expand=dns_names", timeout=15, headers=_UA)
    out = set()
    if r.ok:
        for row in r.json():
            out |= _clean(row.get("dns_names", []), domain)
    return out


def _src_certkit(domain: str) -> set:
    r = requests.get(f"https://ct.certkit.io/search?domain={domain}", timeout=15, headers=_UA)
    out = set()
    if r.ok:
        for row in r.json().get("results", []):
            out |= _clean([row.get("commonName")] + (row.get("dnsNames") or []), domain)
    return out


def _src_hackertarget(domain: str) -> set:
    r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15, headers=_UA)
    if r.ok and "," in r.text and "error" not in r.text.lower():
        return _clean((line.split(",")[0] for line in r.text.splitlines()), domain)
    return set()


_PASSIVE_SOURCES = [_src_crtsh, _src_certspotter, _src_certkit, _src_hackertarget]


def _crtsh(domain: str) -> list[str]:
    """Passive subdomain discovery: query ALL certificate-transparency / public
    sources concurrently and union the results — each source finds names the
    others miss. One source failing (e.g. crt.sh 502) never drops the rest."""
    names: set = set()
    def run(fn):
        try:
            return fn(domain)
        except Exception:
            return set()
    with ThreadPoolExecutor(max_workers=len(_PASSIVE_SOURCES)) as ex:
        for got in ex.map(run, _PASSIVE_SOURCES):
            names |= got
    return sorted(names)


@app.post("/api/scan")
def scan(q: Query):
    domain = q.domain.strip().rstrip(".")
    if not domain:
        return JSONResponse({"error": "domain required"}, status_code=400)
    ns = q.resolver
    res = _resolver(ns)

    # apex records via direct queries (no wordlist)
    apex = {}
    for rtype in APEX_TYPES:
        try:
            apex[rtype] = [r.to_text() for r in res.resolve(domain, rtype)]
        except Exception:
            apex[rtype] = []

    # wildcard detection: does a random label resolve?
    wildcard = False
    try:
        res.resolve(f"{secrets.token_hex(6)}.{domain}", "A")
        wildcard = True
    except Exception:
        pass

    # nameservers to try AXFR against: user-supplied resolver(s) first, else the zone's NS
    ns_names = [x.rstrip(".") for x in apex.get("NS", [])]
    targets: list[tuple[str, str]] = []            # (label, ip)
    for t in _split(ns) or ns_names:
        if any(c.isalpha() for c in t):            # NS hostname -> resolve to IPs
            try:
                targets += [(t, str(a)) for a in _resolver(ns).resolve(t, "A")]
            except Exception:
                pass
        else:
            targets.append((t, t))

    rows, axfr_from, method = [], [], ""
    seen = set()
    for label, ip in targets:
        try:
            for r in _axfr(domain, ip):
                k = (r["host"], r["type"], r["value"])
                if k not in seen:
                    seen.add(k); rows.append(r)
            axfr_from.append(label)
        except Exception:
            continue

    if rows:
        method = "AXFR zone transfer from " + ", ".join(sorted(set(axfr_from)))
    else:
        method = "AXFR refused — direct apex record queries only"
        for rtype in APEX_TYPES:
            for v in apex.get(rtype, []):
                rows.append({"host": domain, "type": rtype, "value": v,
                             "reverse": "", "owner": "", "http": "", "source": "apex"})

    # passive discovery via crt.sh certificate-transparency logs
    passive_names = []
    if q.passive:
        seen_hosts = {r["host"] for r in rows}
        cands = [n for n in _crtsh(domain) if n not in seen_hosts][:400]
        passive_names = cands
        with ThreadPoolExecutor(max_workers=20) as ex:
            for res_rows in ex.map(lambda h: _resolve_host(h, ns), cands):
                for r in res_rows:
                    k = (r["host"], r["type"], r["value"])
                    if k not in seen:
                        seen.add(k); rows.append(r)

    # enrich A/AAAA rows (reverse DNS, ASN, banners) concurrently
    a_rows = [r for r in rows if r["type"] in ("A", "AAAA")]
    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(lambda r: _enrich(r, ns, q.grab_http), a_rows))

    if q.passive:
        method += f" + passive CT/DNS ({len(passive_names)} names)"
    rows.sort(key=lambda r: (r["host"], r["type"]))
    counts = {"internal": sum(r.get("scope") == "internal" for r in rows),
              "public": sum(r.get("scope") == "public" for r in rows)}
    return {"domain": domain, "resolver": ns or "system", "method": method,
            "wildcard": wildcard, "counts": counts, "apex": apex, "rows": rows}


@app.post("/api/export")
def export(payload: dict):
    domain = payload.get("domain", "domain")
    rows = payload.get("rows", [])
    apex = payload.get("apex", {})
    hdr_font, hdr_fill = Font(bold=True, color="FFFFFF"), PatternFill("solid", fgColor="1F3B57")

    wb = Workbook()
    s = wb.active; s.title = "Summary"
    s["B2"] = f"DNS Explorer report for {domain}"; s["B2"].font = Font(bold=True, size=14)
    s["B3"] = payload.get("method", ""); s["B3"].font = Font(italic=True, color="666666")
    s["B5"] = "Apex records"; s["B5"].font = Font(bold=True)
    r = 6
    for k, v in apex.items():
        for item in (v or []):
            s.cell(r, 2, k); s.cell(r, 3, item); r += 1
    s.column_dimensions["B"].width = 12; s.column_dimensions["C"].width = 70

    d = wb.create_sheet("DNS Records")
    cols = ["Host", "Type", "Value / IP", "Scope", "Reverse DNS", "Netblock Owner", "HTTP Services", "Source"]
    for c, name in enumerate(cols, 1):
        cell = d.cell(1, c, name); cell.font = hdr_font; cell.fill = hdr_fill
    for i, row in enumerate(rows, 2):
        for c, key in enumerate(("host", "type", "value", "scope", "reverse", "owner", "http", "source"), 1):
            d.cell(i, c, row.get(key))
    for col, w in zip("ABCDEFGH", (34, 8, 40, 10, 30, 44, 40, 10)):
        d.column_dimensions[col].width = w
    wrap = Alignment(wrap_text=True, vertical="top")
    for r_ in d.iter_rows(min_row=2):
        for c in r_:
            c.alignment = wrap

    buf = io.BytesIO(); wb.save(buf); buf.seek(0)
    return StreamingResponse(
        buf, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{domain}-dns.xlsx"'})


app.mount("/", StaticFiles(directory="static", html=True), name="static")
