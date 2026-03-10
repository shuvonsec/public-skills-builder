#!/usr/bin/env python3
"""
Public Skills Builder
Fetches public disclosed bug bounty reports from HackerOne + GitHub writeup repos
and generates Claude AI skill files organized by vulnerability class.

Sources:
  1. HackerOne REST API — public disclosed reports (requires API key)
  2. GitHub writeup collections — awesome-bug-bounty-writeups, etc.
  3. HackerOne hacktivity web feed — no auth needed

Usage:
  python public_skills_builder.py [--source h1|github|all] [--program HANDLE]
                                   [--vuln-type TYPE] [--limit N] [--out DIR]
"""

import os
import re
import sys
import json
import time
import argparse
import textwrap
import requests
from pathlib import Path
from collections import defaultdict

try:
    import anthropic
except ImportError:
    print("[!] Missing: pip install anthropic requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

H1_API_BASE   = "https://api.hackerone.com/v1"
H1_WEB_GQL    = "https://hackerone.com/graphql"

GITHUB_WRITEUP_REPOS = [
    # (owner, repo, path_to_writeups_list_or_readme)
    ("ngalongc", "bug-bounty-reference", "README.md"),
    ("devanshbatham", "Awesome-Bugbounty-Writeups", "README.md"),
    ("djadmin", "awesome-bug-bounty", "README.md"),
]

VULN_KEYWORDS = {
    "idor":            ["idor", "insecure direct object", "broken access control", "horizontal privilege"],
    "ssrf":            ["ssrf", "server-side request forgery", "internal metadata"],
    "xss":             ["xss", "cross-site scripting", "stored xss", "reflected xss", "dom xss"],
    "sqli":            ["sql injection", "sqli", "blind sql", "error-based sql"],
    "rce":             ["rce", "remote code execution", "command injection", "code execution"],
    "auth-bypass":     ["authentication bypass", "auth bypass", "2fa bypass", "mfa bypass"],
    "oauth":           ["oauth", "oidc", "jwt", "pkce", "token theft", "open redirect"],
    "race-condition":  ["race condition", "toctou", "double-spend", "concurrent"],
    "business-logic":  ["business logic", "price manipulation", "logic flaw", "workflow bypass"],
    "graphql":         ["graphql", "introspection", "batching", "alias bypass"],
    "cache-poison":    ["cache poison", "cache deception", "web cache"],
    "xxe":             ["xxe", "xml external entity", "xml injection"],
    "upload":          ["file upload", "unrestricted upload", "webshell", "path traversal"],
    "ssti":            ["ssti", "server-side template", "template injection"],
    "csrf":            ["csrf", "cross-site request forgery"],
    "subdomain":       ["subdomain takeover", "dangling dns", "cname takeover"],
    "llm-ai":          ["prompt injection", "llm", "ai chatbot", "indirect injection", "ascii smuggling"],
    "crypto":          ["timing attack", "hmac", "signature bypass", "weak crypto", "replay attack"],
}


# ---------------------------------------------------------------------------
# Source 1: HackerOne REST API (public disclosed reports)
# ---------------------------------------------------------------------------

def fetch_h1_disclosed(api_key: str, program: str | None, limit: int) -> list[dict]:
    """
    Fetch publicly disclosed resolved reports via H1 REST API.
    Requires a free H1 account API key.
    Endpoint: GET /v1/hackers/me/reports (own) or program-specific disclosed.
    """
    if ":" not in api_key:
        print("[!] H1_API_KEY must be 'identifier:token'")
        return []

    identifier, token = api_key.split(":", 1)
    auth = (identifier, token)
    headers = {"Accept": "application/json"}
    reports = []
    page = 1

    print(f"[*] Fetching H1 disclosed reports (limit={limit})...")

    while len(reports) < limit:
        params = {
            "filter[state][]":     ["resolved"],
            "filter[disclosed]":   True,
            "page[size]":          min(100, limit - len(reports)),
            "page[number]":        page,
            "sort":                "-created_at",
        }
        if program:
            params["filter[program][]"] = program

        try:
            resp = requests.get(
                f"{H1_API_BASE}/hackers/me/reports",
                auth=auth, headers=headers, params=params, timeout=15
            )
        except requests.RequestException as e:
            print(f"[!] H1 API error: {e}")
            break

        if resp.status_code == 401:
            print("[!] H1 auth failed. Check H1_API_KEY in .env")
            break
        if resp.status_code == 429:
            print("[*] Rate limited. Waiting 30s...")
            time.sleep(30)
            continue
        if not resp.ok:
            print(f"[!] H1 API returned {resp.status_code}")
            break

        data = resp.json().get("data", [])
        if not data:
            break

        for item in data:
            attrs = item.get("attributes", {})
            rels  = item.get("relationships", {})
            weakness = (
                rels.get("weakness", {})
                    .get("data", {}) or {}
            )
            severity = (
                rels.get("severity", {})
                    .get("data", {}) or {}
            )
            reports.append({
                "source":      "hackerone",
                "id":          item.get("id"),
                "title":       attrs.get("title", ""),
                "severity":    severity.get("attributes", {}).get("rating", ""),
                "weakness":    weakness.get("attributes", {}).get("name", ""),
                "description": attrs.get("vulnerability_information", ""),
                "impact":      attrs.get("impact", ""),
                "program":     rels.get("program", {}).get("data", {}).get("attributes", {}).get("handle", ""),
                "url":         f"https://hackerone.com/reports/{item.get('id')}",
                "disclosed_at": attrs.get("disclosed_at", ""),
            })

        if len(data) < 100:
            break
        page += 1
        time.sleep(0.3)

    print(f"[+] Fetched {len(reports)} H1 reports")
    return reports[:limit]


# ---------------------------------------------------------------------------
# Source 2: HackerOne public hacktivity (no auth needed)
# ---------------------------------------------------------------------------

def fetch_h1_hacktivity(limit: int, program: str | None = None) -> list[dict]:
    """
    Fetch public hacktivity from HackerOne's web GraphQL (no auth).
    Returns disclosed reports from the public feed.
    """
    reports = []
    cursor = None
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    }

    print(f"[*] Fetching H1 public hacktivity feed (limit={limit})...")

    query = """
    query HacktivityFeed($after: String, $program: [String]) {
      hacktivity: reports(
        filter: {
          reporter: [],
          disclosed_at__lt: "2099-01-01"
          program: $program
        }
        first: 25
        after: $after
        order_by: {field: disclosed_at, direction: DESC}
      ) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          title
          disclosed_at
          severity { rating }
          weakness { name }
          team { handle name }
        }
      }
    }
    """

    # Fallback: use the simpler public endpoint
    simple_query = """
    query {
      reports(filter: {reporter: [], disclosed_at__lt: "2099-01-01"}, first: 25) {
        nodes {
          id title disclosed_at
          severity { rating }
          weakness { name }
          team { handle }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """

    while len(reports) < limit:
        variables = {"after": cursor}
        if program:
            variables["program"] = [program]

        try:
            resp = requests.post(
                H1_WEB_GQL,
                headers=headers,
                json={"query": simple_query},
                timeout=15,
            )
        except requests.RequestException as e:
            print(f"[!] Hacktivity fetch error: {e}")
            break

        if not resp.ok:
            print(f"[!] Hacktivity returned {resp.status_code}")
            break

        data = resp.json()
        if "errors" in data:
            print(f"[!] GraphQL errors: {data['errors']}")
            break

        nodes = data.get("data", {}).get("reports", {}).get("nodes", [])
        page_info = data.get("data", {}).get("reports", {}).get("pageInfo", {})

        for node in nodes:
            if node.get("disclosed_at"):
                reports.append({
                    "source":      "hackerone_public",
                    "id":          node.get("id"),
                    "title":       node.get("title", ""),
                    "severity":    node.get("severity", {}).get("rating", "") if node.get("severity") else "",
                    "weakness":    node.get("weakness", {}).get("name", "") if node.get("weakness") else "",
                    "description": "",  # public feed doesn't include body
                    "impact":      "",
                    "program":     node.get("team", {}).get("handle", "") if node.get("team") else "",
                    "url":         f"https://hackerone.com/reports/{node.get('id')}",
                    "disclosed_at": node.get("disclosed_at", ""),
                })

        if not page_info.get("hasNextPage") or not nodes:
            break

        cursor = page_info.get("endCursor")
        time.sleep(0.5)

    print(f"[+] Fetched {len(reports)} public hacktivity reports")
    return reports[:limit]


# ---------------------------------------------------------------------------
# Source 3: GitHub writeup collections
# ---------------------------------------------------------------------------

def fetch_github_writeups(limit: int) -> list[dict]:
    """
    Parse awesome writeup repos from GitHub and extract report links + titles.
    No auth needed for public repos.
    """
    github_token = os.getenv("GITHUB_TOKEN", "")
    headers = {"User-Agent": "public-skills-builder"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    reports = []
    print("[*] Fetching GitHub writeup collections...")

    for owner, repo, path in GITHUB_WRITEUP_REPOS:
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{path}"
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if not resp.ok:
                # try main branch
                resp = requests.get(
                    url.replace("/master/", "/main/"),
                    headers=headers, timeout=15
                )
            if not resp.ok:
                print(f"[!] Could not fetch {owner}/{repo}")
                continue
        except requests.RequestException:
            continue

        content = resp.text
        # Extract markdown links: [title](url)
        links = re.findall(r'\[([^\]]+)\]\((https?://[^\)]+)\)', content)

        for title, link_url in links:
            if len(reports) >= limit:
                break
            # Only keep writeup URLs (not repo links or docs)
            if any(kw in link_url.lower() for kw in [
                "medium.com", "infosec", "writeup", "hackerone.com/reports",
                "blog", "notion.so", "github.io", "portswigger", "bugcrowd"
            ]):
                vuln_class = classify_report(title, "")
                reports.append({
                    "source":      f"github:{owner}/{repo}",
                    "id":          re.sub(r'[^a-z0-9]', '-', title.lower())[:40],
                    "title":       title,
                    "severity":    "",
                    "weakness":    vuln_class,
                    "description": f"Public writeup: {title}",
                    "impact":      "",
                    "program":     "",
                    "url":         link_url,
                    "disclosed_at": "",
                })

        print(f"[+] {owner}/{repo}: {len(links)} links found")
        time.sleep(0.3)

    print(f"[+] Total GitHub writeups: {len(reports)}")
    return reports[:limit]


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify_report(title: str, weakness: str) -> str:
    """Map a report to a vuln class based on title + weakness name."""
    text = (title + " " + weakness).lower()
    for vuln_class, keywords in VULN_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return vuln_class
    return "misc"


def group_by_vuln(reports: list[dict]) -> dict[str, list[dict]]:
    """Group reports by vuln class."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in reports:
        cls = classify_report(r["title"], r.get("weakness", ""))
        r["vuln_class"] = cls
        groups[cls].append(r)
    return dict(groups)


# ---------------------------------------------------------------------------
# AI Skill Generation
# ---------------------------------------------------------------------------

SKILL_PROMPT = """You are a senior bug bounty hunter building a reusable hunting skill.

You will receive {count} public bug bounty reports about: **{vuln_class}**

Your job is to extract GENERALIZABLE hunting knowledge — NOT to summarize individual reports.

Generate a hunting skill with these exact sections:

## Crown Jewel Targets
What makes this vuln class high-value? Where does it pay most? What asset types?

## Attack Surface Signals
How do you recognize this attack surface in the wild? (URL patterns, response headers, JS patterns, tech stack signals)

## Step-by-Step Hunting Methodology
Numbered steps. Specific. Actionable. What do you test first, second, third?

## Payload & Detection Patterns
Concrete payloads, grep patterns, or curl commands. Format as code blocks.

## Common Root Causes
Why do developers introduce this bug? What shortcuts/mistakes cause it?

## Bypass Techniques
How do defenders try to block this, and how do hunters bypass those defenses?

## Gate 0 Validation
3-question test to confirm this is real before writing the report:
1. What can the attacker DO right now?
2. What does the victim LOSE?
3. Can it be reproduced in 10 minutes from scratch?

## Real Impact Examples
2-3 anonymized attack scenarios from the reports below that show actual business impact.

Reports:
{reports}

Write the skill in clean markdown. No preamble. Start directly with ## Crown Jewel Targets.
"""


def generate_skill(client: anthropic.Anthropic, vuln_class: str, reports: list[dict]) -> str:
    """Send grouped reports to Claude and get a skill file back."""

    # Build report summaries (no PII/URLs redacted for public reports)
    report_text = ""
    for i, r in enumerate(reports[:30], 1):  # cap at 30 per skill
        report_text += f"\n### Report {i}: {r['title']}\n"
        if r.get("severity"):
            report_text += f"Severity: {r['severity']}\n"
        if r.get("weakness"):
            report_text += f"Weakness: {r['weakness']}\n"
        if r.get("program"):
            report_text += f"Program: {r['program']}\n"
        if r.get("url"):
            report_text += f"URL: {r['url']}\n"
        if r.get("description") and len(r["description"]) > 50:
            desc = r["description"][:2000]
            report_text += f"Description:\n{desc}\n"
        if r.get("impact") and len(r["impact"]) > 20:
            report_text += f"Impact: {r['impact'][:500]}\n"
        report_text += "\n"

    prompt = SKILL_PROMPT.format(
        vuln_class=vuln_class.replace("-", " ").upper(),
        count=len(reports),
        reports=report_text,
    )

    for attempt in range(3):
        try:
            msg = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text
        except anthropic.RateLimitError:
            wait = 30 * (attempt + 1)
            print(f"[*] Rate limited, waiting {wait}s...")
            time.sleep(wait)
        except anthropic.APIError as e:
            print(f"[!] Claude API error: {e}")
            break

    return f"# {vuln_class}\n\n*Generation failed. Try again.*\n"


def write_skill_file(out_dir: Path, vuln_class: str, content: str, report_count: int, sources: list[str]):
    """Write a skill file with YAML frontmatter."""
    # Extract a one-liner description from the content
    first_line = ""
    for line in content.split("\n"):
        line = line.strip()
        if line and not line.startswith("#") and len(line) > 30:
            first_line = line[:120]
            break

    name = vuln_class.lower().replace(" ", "-").replace("_", "-")
    description = (
        f"Hunting skill for {vuln_class.replace('-', ' ')} vulnerabilities. "
        f"Built from {report_count} public bug bounty reports. "
        f"Use when hunting {vuln_class.replace('-', ' ')} on any target."
    )[:300]

    frontmatter = f"""---
name: hunt-{name}
description: {description}
sources: {", ".join(set(sources))}
report_count: {report_count}
---

"""
    filepath = out_dir / f"hunt-{name}.md"
    filepath.write_text(frontmatter + content, encoding="utf-8")
    print(f"[+] Written: {filepath.name} ({report_count} reports)")
    return filepath


def write_index(out_dir: Path, skills: list[dict]):
    """Write a README index of all generated skills."""
    lines = [
        "# Public Bug Bounty Skills",
        "",
        f"Generated from {sum(s['count'] for s in skills)} public reports across {len(skills)} vulnerability classes.",
        "",
        "| Skill | Reports | Sources |",
        "|-------|---------|---------|",
    ]
    for s in sorted(skills, key=lambda x: -x["count"]):
        lines.append(f"| [{s['name']}]({s['file']}) | {s['count']} | {s['sources']} |")

    lines += [
        "",
        "## Usage with Claude Code",
        "```bash",
        "# Load a skill",
        "cat skills/hunt-idor.md | claude",
        "",
        "# Or reference in your CLAUDE.md",
        "cat skills/hunt-ssrf.md >> ~/.claude/CLAUDE.md",
        "```",
    ]

    (out_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Index written: {out_dir}/README.md")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Build Claude AI hunting skills from public bug bounty reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          # Fetch from all sources, generate all vuln class skills
          python public_skills_builder.py

          # Only HackerOne public feed, only IDOR + SSRF
          python public_skills_builder.py --source h1 --vuln-type idor ssrf

          # Specific program
          python public_skills_builder.py --source h1 --program shopify --limit 200

          # GitHub writeups only
          python public_skills_builder.py --source github --limit 100
        """),
    )
    p.add_argument("--source", choices=["h1", "h1-public", "github", "all"], default="all")
    p.add_argument("--program", help="H1 program handle (e.g. shopify, hackerone)")
    p.add_argument("--vuln-type", nargs="+", choices=list(VULN_KEYWORDS.keys()),
                   help="Only generate skills for these vuln classes")
    p.add_argument("--limit", type=int, default=500, help="Max reports to fetch (default: 500)")
    p.add_argument("--out", default="skills", help="Output directory (default: skills/)")
    p.add_argument("--min-reports", type=int, default=3,
                   help="Min reports per class to generate a skill (default: 3)")
    return p.parse_args()


def load_env():
    """Load .env file if present."""
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def main():
    load_env()
    args = parse_args()

    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if not anthropic_key:
        print("[!] Set ANTHROPIC_API_KEY in .env or environment")
        sys.exit(1)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    client = anthropic.Anthropic(api_key=anthropic_key)

    # --- Fetch reports ---
    all_reports: list[dict] = []

    try:
        if args.source in ("h1", "all"):
            h1_key = os.getenv("H1_API_KEY", "")
            if h1_key:
                all_reports += fetch_h1_disclosed(h1_key, args.program, args.limit)
            else:
                print("[!] H1_API_KEY not set — skipping private H1 reports")

        if args.source in ("h1-public", "all"):
            all_reports += fetch_h1_hacktivity(args.limit, args.program)

        if args.source in ("github", "all"):
            all_reports += fetch_github_writeups(args.limit // 2)

    except KeyboardInterrupt:
        print("\n[*] Interrupted during fetch. Proceeding with collected reports...")

    if not all_reports:
        print("[!] No reports collected. Check your API keys and source settings.")
        sys.exit(1)

    print(f"\n[*] Total reports collected: {len(all_reports)}")

    # --- Group by vuln class ---
    groups = group_by_vuln(all_reports)

    if args.vuln_type:
        groups = {k: v for k, v in groups.items() if k in args.vuln_type}

    print(f"[*] Vuln classes found: {', '.join(f'{k}({len(v)})' for k, v in sorted(groups.items(), key=lambda x: -len(x[1])))}")

    # --- Generate skills ---
    skills_written = []
    try:
        for vuln_class, reports in sorted(groups.items(), key=lambda x: -len(x[1])):
            if len(reports) < args.min_reports:
                print(f"[~] Skipping {vuln_class} ({len(reports)} reports < min {args.min_reports})")
                continue

            print(f"\n[*] Generating skill: {vuln_class} ({len(reports)} reports)...")
            content = generate_skill(client, vuln_class, reports)

            sources = list(set(r["source"].split(":")[0] for r in reports))
            filepath = write_skill_file(out_dir, vuln_class, content, len(reports), sources)

            skills_written.append({
                "name":    f"hunt-{vuln_class}",
                "file":    filepath.name,
                "count":   len(reports),
                "sources": ", ".join(sources),
            })
            time.sleep(1)  # be nice to the API

    except KeyboardInterrupt:
        print("\n[*] Interrupted. Saving index for skills generated so far...")

    if skills_written:
        write_index(out_dir, skills_written)
        print(f"\n[+] Done. {len(skills_written)} skills written to {out_dir}/")
    else:
        print("[!] No skills generated.")


if __name__ == "__main__":
    main()
