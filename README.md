# CyberBrief Daily Intelligence Feed

A cyberpunk-themed daily cybersecurity intelligence feed that automatically pulls data from multiple sources and displays it in a neon terminal-style interface.

## What's inside

```
.
├── README.md                        ← you are here
├── data.json                        ← daily intel data (auto-updated)
├── scraper.py                       ← daily data collection script
├── .github/workflows/daily-brief.yml ← GitHub Actions automation
├── colors_and_type.css              ← design system tokens
└── ui_kits/
    └── brief/
        ├── index.html               ← the live brief (fetches data.json)
        └── README.md
```

## How it works

### 1. Daily Data Collection (7am CST)

Every day at 7am CST, GitHub Actions runs `scraper.py` which:
- Scrapes cybersecurity news from **SecurityWeek**, **BleepingComputer**, **Dark Reading**, **CISA KEV**, **The Hacker News**
- Filters items by severity and impact (10–20 items per day)
- Structures data into JSON format
- Commits and pushes `data.json` to this repo

### 2. Live Brief Display

The brief at `ui_kits/brief/index.html`:
- Fetches `data.json` on page load
- Displays 4 collapsible sections: **Breach Report**, **Vulnerability Tracker**, **Threat Intelligence**, **Situation Report**
- Shows metric tiles (Critical CVEs, High CVEs, Breaches, News)
- Renders source links for each item
- Allows exporting the brief as a plaintext email via "// TRANSMIT REPORT" button

## Data structure

`data.json` contains:

```json
{
  "breach": [
    {
      "org": "Company name",
      "severity": "Critical|High|Medium",
      "date": "Apr 2026",
      "records": "# of records affected",
      "summary": "Brief description of the breach",
      "sources": [
        {"label": "Source name", "url": "https://..."}
      ]
    }
  ],
  "cve": [
    {
      "cve_id": "CVE-2026-12345",
      "product": "Product name",
      "vendor": "Vendor name",
      "severity": "Critical|High|Medium",
      "cvss": "9.8",
      "patch_status": "Patch available|CISA KEV|Exploited",
      "summary": "Description of the vulnerability",
      "sources": [...]
    }
  ],
  "threat": [
    {
      "actor": "APT28 (Forest Blizzard)",
      "type": "Nation-state|Cybercrime|Hacktivist",
      "targets": "Who they target",
      "ttp": "Tactics, techniques, procedures",
      "iocs": ["indicator1", "indicator2"],
      "summary": "Description of the threat",
      "sources": [...]
    }
  ],
  "news": [
    {
      "title": "Headline",
      "category": "Regulatory|Law Enforcement|Threat Trends",
      "source": "Publication name",
      "date": "May 1, 2026",
      "summary": "Summary of the news",
      "sources": [...]
    }
  ]
}
```

## GitHub Actions Setup

The workflow (`.github/workflows/daily-brief.yml`) is configured to:

1. **Run at 7am CST daily** (via cron schedule `0 13 * * *` UTC)
2. **Execute `scraper.py`** to fetch and filter data
3. **Commit and push** to `main` branch if changes detected
4. **Auto-retry** on transient failures

### Manual trigger

You can also manually trigger the update from the GitHub Actions tab:
1. Go to **Actions** → **CyberBrief Daily Update**
2. Click **Run workflow** → **Run workflow**

### Adjusting the time

The workflow uses UTC time. To change the daily run time:

- Edit `.github/workflows/daily-brief.yml`
- Modify the cron line: `- cron: '0 13 * * *'`
  - First `0` = minute (0–59)
  - Second `13` = hour in UTC (0–23)
  - Replace `13` with your desired UTC hour

**CST to UTC conversion:**
- 7am CST = 1pm UTC (13:00) — standard time
- 7am CDT = 12pm UTC (12:00) — daylight saving time

## Deploying

### Prerequisites

- GitHub repository (`SecOps-DCTX`)
- Python 3.11+
- Git

### Steps

1. **Clone or create the repo:**
   ```bash
   git clone https://github.com/SecOps-DCTX/cyberbrief.git
   cd cyberbrief
   ```

2. **Add these files:**
   - `data.json`
   - `scraper.py`
   - `.github/workflows/daily-brief.yml`
   - `colors_and_type.css`
   - `ui_kits/brief/index.html`
   - `ui_kits/brief/README.md`

3. **Configure Git:**
   ```bash
   git config user.email "your-email@example.com"
   git config user.name "Your Name"
   ```

4. **Commit and push:**
   ```bash
   git add .
   git commit -m "Initial CyberBrief setup"
   git push origin main
   ```

5. **Verify GitHub Actions:**
   - Go to your repo → **Actions** tab
   - You should see **CyberBrief Daily Update** workflow
   - It will run automatically at 7am CST every day

## Viewing the brief

Once deployed, the brief is live at:
```
https://github.com/SecOps-DCTX/cyberbrief/blob/main/ui_kits/brief/index.html
```

Or, to view the rendered HTML directly, use GitHub Pages or a static host:
```
https://your-domain.com/path/to/ui_kits/brief/index.html
```

## Customizing the scraper

The scraper is a template. To add real data collection, edit `scraper.py`:

1. **SecurityWeek RSS:**
   ```
   https://www.securityweek.com/feed/
   ```

2. **BleepingComputer RSS:**
   ```
   https://www.bleepingcomputer.com/feed/
   ```

3. **Dark Reading RSS:**
   ```
   https://www.darkreading.com/rss.xml
   ```

4. **CISA KEV JSON API:**
   ```
   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
   ```

5. **The Hacker News RSS:**
   ```
   https://thehackernews.com/feeds/posts/default
   ```

Each source returns items that you'll parse, score by severity/impact, and insert into the appropriate section (breach/cve/threat/news).

## Design

The brief uses the **CyberBrief Design System** (`colors_and_type.css`):

- **Neon palette:** Cyan (#00f5ff), Pink (#ff2d78), Green (#00ff9d), Red (#ff3a3a), Orange (#ff8c00)
- **Type:** Share Tech Mono (display), Rajdhani (body)
- **Signature:** 2px repeating scanline overlay
- **Components:** Collapsible sections, metric tiles, severity badges, IOC chips, source links

All styling is token-based — update `colors_and_type.css` and all previews + the brief will follow.

## Troubleshooting

### Data not updating

1. Check the **Actions** tab for workflow errors
2. Verify `scraper.py` has correct permissions: `chmod +x scraper.py`
3. Check Git credentials are configured correctly

### Brief not loading

1. Ensure `data.json` exists in the repo root
2. Check browser console for fetch errors
3. Verify CORS if hosting on a different domain

### Cron not firing

1. GitHub Actions are disabled in the repo settings? Check **Settings** → **Actions** → **General**
2. Verify the workflow file (`.github/workflows/daily-brief.yml`) is valid YAML

## Next steps

1. **Push to GitHub** — add all files to your repo
2. **Test the workflow** — manually trigger from Actions tab
3. **Implement real scrapers** in `scraper.py` for each news source
4. **Monitor the first run** — check for any errors in the workflow logs
5. **Set up GitHub Pages** (optional) to host the brief as a live website

---

**Questions?** Check the inline comments in `scraper.py` for implementation hints, or refer to the design system `README.md` for styling details.
