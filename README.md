# 🐅 QR Tiger King 👑

**Integrated QR Tiger Subdomain Takeover Scanner**

Discover domains vulnerable to subdomain takeover via [QR Tiger's](https://www.qrcode-tiger.com/) "Own Short Domain" feature. When companies point `qr.<domain>` to QR Tiger's infrastructure (`qr1.be`) via CNAME but stop using the service, the subdomain becomes claimable by anyone — QR Tiger performs no domain ownership verification.

This tool automates the full pipeline: DNS reconnaissance → CNAME discovery → HTTP verification.

📝 **Full write-up:** [Introducing QR Jacking — When Your Branded QR Codes Aren't Yours](https://jumpycastle.dev/introducing-qr-jacking-when-your-branded-qr-codes-arent-yours-b3621cdfac1f)

---

## How It Works

1. **DNS Scan** — Queries `qr.<domain>` for CNAME records across up to 1M domains in parallel
2. **Inline HTTP Verify** — As each CNAME → `qr1.be` hit is found, immediately curls it to classify as:
   - **UNCLAIMED** — Returns `Forbidden` (claimable in QR Tiger's dashboard)
   - **CLAIMED** — Serves content or redirects (already owned by someone)

## Quick Start

```bash
# Clone
git clone https://github.com/jumpycastle/qr-tiger-king.git
cd qr-tiger-king

# Install dependencies
pip install dnspython requests tqdm

# Run against Tranco Top 1M (default)
python3 qr_tiger_king.py

# Run against your own domain list
python3 qr_tiger_king.py --scan-only domains.txt

# DNS scan only (skip HTTP check)
python3 qr_tiger_king.py --dns-only
```

## Usage

```
python3 qr_tiger_king.py [OPTIONS]

Options:
  --source NAME       Domain list: tranco (default), majestic, umbrella
  --scan-only FILE    Scan your own domain list (one domain per line)
  --limit N           Only scan the top N domains (default: all)
  --threads N         Parallel DNS workers (default: 50)
  --dns-only          Skip HTTP verification (DNS scan only)
  -h, --help          Show help
```

### Examples

```bash
# Scan Tranco Top 1M (downloads automatically)
python3 qr_tiger_king.py

# Scan Majestic Million
python3 qr_tiger_king.py --source majestic

# Scan Cisco Umbrella Top 1M
python3 qr_tiger_king.py --source umbrella

# Scan only the top 100K domains with 100 threads
python3 qr_tiger_king.py --limit 100000 --threads 100

# Scan a custom list of domains
python3 qr_tiger_king.py --scan-only my_targets.txt

# DNS only — just find CNAME → qr1.be, skip HTTP check
python3 qr_tiger_king.py --dns-only --limit 50000
```

### Custom Domain Lists

Create a text file with one domain per line:

```
example.com
university.edu
company.co.uk
```

The script automatically strips protocols (`https://`), paths, and `www.` prefixes, so messy lists work fine:

```
https://www.example.com/about
http://company.co.uk
university.edu
```

Then run:

```bash
python3 qr_tiger_king.py --scan-only domains.txt
```

## Output

Results are saved to `qr_king_<timestamp>/`:

| File | Description |
|------|-------------|
| `vulnerable_dns.csv` | All domains with CNAME → `qr1.be` |
| `unclaimed.csv` | Domains returning Forbidden (claimable in QR Tiger) |
| `claimed.csv` | Domains already serving content |
| `full_results.csv` | All HTTP results with status and category |
| `raw_responses/` | Full HTTP response body per domain |
| `has_qr_subdomain.csv` | Domains where `qr.*` resolves but not to `qr1.be` |
| `no_record.txt` | Domains with no `qr.*` DNS record |
| `domains.txt` | Full domain list used for scanning |

## The Vulnerability

**CWE-284 (Improper Access Control)** — QR Tiger allows any authenticated user to claim a custom domain without verifying ownership. If a company previously configured `qr.company.com` → `qr1.be` and stopped using QR Tiger without removing the DNS CNAME, an attacker can:

1. Create a free QR Tiger account
2. Add `qr.company.com` as their custom domain
3. Generate QR codes that resolve under the company's subdomain
4. Use the trusted subdomain for phishing, malware delivery, or credential harvesting

The company's side is **CWE-16 (Configuration)** — failure to remove stale DNS records pointing to third-party infrastructure.

## Requirements

- Python 3.7+
- `dnspython` — DNS resolution
- `requests` — HTTP verification
- `tqdm` (optional) — Progress bars

```bash
pip install dnspython requests tqdm
```

## Responsible Disclosure

This tool is intended for **authorized security research and responsible disclosure only**. If you discover vulnerable domains:

1. **Do not claim the domain** unless you have authorization or are conducting a controlled POC
2. Verify findings manually (`dig CNAME qr.<domain>`, browser visit)
3. Identify the domain owner via `whois` or `security.txt`
4. Notify the domain owner with evidence before any public disclosure
5. Consider notifying QR Tiger as well — this is a platform-level architectural issue

## License

MIT

## Credits

- **Farzan Karimi** — [Castling Security](https://castlingsecurity.com)
