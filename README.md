# Public Skills Builder

Build Claude AI hunting skills from **public** bug bounty reports — no private reports needed.

## Sources

| Source | Auth needed | What it fetches |
|--------|-------------|-----------------|
| HackerOne public feed | None | Publicly disclosed reports |
| HackerOne REST API | H1 API key | Your own resolved reports |
| GitHub writeup repos | None (optional token) | 1,200+ community writeups |

## Output

One markdown skill file per vulnerability class, ready to use with Claude Code:

```
skills/
  hunt-idor.md
  hunt-ssrf.md
  hunt-xss.md
  hunt-rce.md
  hunt-oauth.md
  ... (18 vuln classes)
  README.md  ← index
```

Each skill file contains:
- Crown jewel targets
- Attack surface signals
- Step-by-step methodology
- Payloads & grep patterns
- Bypass techniques
- Gate 0 validation checklist

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/public-skills-builder
cd public-skills-builder

python3 -m venv .venv
source .venv/bin/activate
pip install anthropic requests

cp .env.example .env
# Edit .env — add ANTHROPIC_API_KEY (required)
```

## Usage

```bash
# Public GitHub writeups only (just needs Claude API key)
python3 public_skills_builder.py --source github

# HackerOne public disclosed reports (no H1 key needed)
python3 public_skills_builder.py --source h1-public

# Everything — all sources, all vuln classes
python3 public_skills_builder.py --source all --limit 500

# Specific vuln classes only
python3 public_skills_builder.py --vuln-type idor ssrf xss oauth

# Specific H1 program
python3 public_skills_builder.py --source h1 --program shopify --limit 200
```

## Supported Vuln Classes

`idor` `ssrf` `xss` `sqli` `rce` `auth-bypass` `oauth` `race-condition`
`business-logic` `graphql` `cache-poison` `xxe` `upload` `ssti` `csrf`
`subdomain` `llm-ai` `crypto`

## Requirements

- Python 3.10+
- `ANTHROPIC_API_KEY` — from [console.anthropic.com](https://console.anthropic.com)
- `H1_API_KEY` — optional, from [hackerone.com/settings/api_token](https://hackerone.com/settings/api_token)
- `GITHUB_TOKEN` — optional, increases GitHub API rate limits
