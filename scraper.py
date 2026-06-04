#!/usr/bin/env python3
"""
CyberBrief RSS Scraper with Item Aging & Archive System

WHAT IT DOES (each run):
1. Pulls fresh items from real cybersecurity RSS feeds (working article links)
2. Classifies each item into breach / cve / threat / news by keyword
3. Adds NEW items (deduped against active + archive) at age 0
4. Ages every existing item by +1
5. Moves items past max_age into archive.json
6. Caps each active section to MAX_PER_SECTION (newest kept)

The GitHub Actions workflow handles the git commit/push after this runs.
"""

import json
import os
import re
import html
from datetime import datetime
import logging

import feedparser  # pip install feedparser

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---- RSS feeds (all publish real, working article links) -------------------
FEEDS = [
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News",  "https://feeds.feedburner.com/TheHackersNews"),
    ("SecurityWeek",     "https://www.securityweek.com/feed/"),
    ("Dark Reading",     "https://www.darkreading.com/rss.xml"),
    ("Krebs on Security","https://krebsonsecurity.com/feed/"),
]

MAX_PER_SECTION = 12          # cap active items per section
MAX_NEW_PER_RUN = 8           # cap new items pulled per section per run


class CyberBriefScraper:
    def __init__(self):
        self.data_file = 'data.json'
        self.archive_file = 'archive.json'
        self.max_age = 4       # archive after 4 refreshes (~2 days at 2x daily)

    # ---- file IO -----------------------------------------------------------
    def _load(self, path):
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Could not parse {path}: {e}")
        return {'breach': [], 'cve': [], 'threat': [], 'news': []}

    def load_data(self):
        return self._load(self.data_file)

    def load_archive(self):
        return self._load(self.archive_file)

    def save_data(self, data):
        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)

    def save_archive(self, archive):
        with open(self.archive_file, 'w') as f:
            json.dump(archive, f, indent=2)

    # ---- classification ----------------------------------------------------
    @staticmethod
    def classify(title, summary):
        text = f"{title} {summary}".lower()
        # CVE first — most specific
        if re.search(r'cve-\d{4}-\d+', text) or any(k in text for k in
                ['vulnerability', 'zero-day', 'zero day', 'rce', 'patch tuesday',
                 'flaw', 'exploit', 'buffer overflow', 'privilege escalation']):
            return 'cve'
        if any(k in text for k in
                ['breach', 'data leak', 'leaked', 'exposed', 'stolen data',
                 'data theft', 'records exposed', 'database exposed']):
            return 'breach'
        if any(k in text for k in
                ['ransomware', 'apt', 'threat actor', 'hacking group', 'botnet',
                 'malware', 'phishing campaign', 'nation-state', 'trojan', 'backdoor']):
            return 'threat'
        return 'news'

    @staticmethod
    def severity_from(text):
        t = text.lower()
        if any(k in t for k in ['critical', 'actively exploited', 'zero-day', 'emergency']):
            return 'Critical'
        if any(k in t for k in ['high', 'severe', 'widespread']):
            return 'High'
        if any(k in t for k in ['medium', 'moderate']):
            return 'Medium'
        return 'High'

    @staticmethod
    def clean(text):
        text = re.sub(r'<[^>]+>', '', text or '')      # strip HTML tags
        text = html.unescape(text).strip()
        return re.sub(r'\s+', ' ', text)

    def build_item(self, section, title, link, summary, source_name):
        title = self.clean(title)
        summary = self.clean(summary)
        if len(summary) > 320:
            summary = summary[:317].rsplit(' ', 1)[0] + '...'
        sources = [{"label": source_name, "url": link}]
        base = {"summary": summary or title, "age": 0, "sources": sources,
                "date": datetime.now().strftime('%b %d, %Y')}

        if section == 'breach':
            return {**base, "org": title, "severity": self.severity_from(title + summary),
                    "records": "See source"}
        if section == 'cve':
            m = re.search(r'cve-\d{4}-\d+', (title + ' ' + summary).lower())
            return {**base, "cve_id": (m.group(0).upper() if m else title[:60]),
                    "vendor": source_name, "severity": self.severity_from(title + summary)}
        if section == 'threat':
            return {**base, "actor": title, "severity": self.severity_from(title + summary)}
        return {**base, "title": title, "category": "news"}

    # ---- fetch -------------------------------------------------------------
    def fetch_new(self, existing_keys):
        """Return {section: [items]} of fresh, deduped items from RSS."""
        new = {'breach': [], 'cve': [], 'threat': [], 'news': []}
        for source_name, url in FEEDS:
            try:
                logger.info(f"Fetching {source_name} ...")
                feed = feedparser.parse(url)
                if not feed.entries:
                    logger.warning(f"  no entries from {source_name}")
                    continue
                for entry in feed.entries[:25]:
                    title = entry.get('title', '')
                    link = entry.get('link', '')
                    summary = entry.get('summary', entry.get('description', ''))
                    if not title or not link:
                        continue
                    key = link.strip().lower()
                    if key in existing_keys:
                        continue
                    section = self.classify(title, summary)
                    if len(new[section]) >= MAX_NEW_PER_RUN:
                        continue
                    existing_keys.add(key)
                    new[section].append(self.build_item(section, title, link, summary, source_name))
                logger.info(f"  ok ({len(feed.entries)} entries scanned)")
            except Exception as e:
                logger.warning(f"  failed {source_name}: {e}")
        total = sum(len(v) for v in new.values())
        logger.info(f"New items pulled: {total} "
                    f"(breach {len(new['breach'])}, cve {len(new['cve'])}, "
                    f"threat {len(new['threat'])}, news {len(new['news'])})")
        return new

    # ---- aging -------------------------------------------------------------
    def age_items(self, data, archive):
        for section in ['breach', 'cve', 'threat', 'news']:
            keep = []
            for item in data.get(section, []):
                item['age'] = item.get('age', 0) + 1
                if item['age'] > self.max_age:
                    archive.setdefault(section, []).append(item)
                    name = item.get('org') or item.get('cve_id') or item.get('actor') or item.get('title', '?')
                    logger.info(f"  archived: {name} (age {item['age']})")
                else:
                    keep.append(item)
            data[section] = keep
        return data, archive

    @staticmethod
    def existing_keys(data, archive):
        keys = set()
        for store in (data, archive):
            for section in ['breach', 'cve', 'threat', 'news']:
                for item in store.get(section, []):
                    for s in item.get('sources', []):
                        if s.get('url'):
                            keys.add(s['url'].strip().lower())
        return keys

    # ---- main --------------------------------------------------------------
    def run(self):
        logger.info("=" * 70)
        logger.info("CyberBrief RSS Scraper started "
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("=" * 70)
        try:
            data = self.load_data()
            archive = self.load_archive()

            # 1. age + archive existing items first
            data, archive = self.age_items(data, archive)

            # 2. pull new items (deduped against everything we already have)
            keys = self.existing_keys(data, archive)
            new = self.fetch_new(keys)

            # 3. prepend new items, cap each section
            for section in ['breach', 'cve', 'threat', 'news']:
                data[section] = (new[section] + data.get(section, []))[:MAX_PER_SECTION]

            self.save_data(data)
            self.save_archive(archive)

            counts = {s: len(data[s]) for s in ['breach', 'cve', 'threat', 'news']}
            logger.info(f"Active now: {counts} | "
                        f"archive {sum(len(archive[s]) for s in archive)}")
            logger.info("=" * 70)
            logger.info("✓ CyberBrief update complete")
            logger.info("=" * 70)
            return 0
        except Exception as e:
            logger.error(f"ERROR: {e}")
            logger.error("Keeping existing data files unchanged")
            return 1


if __name__ == '__main__':
    raise SystemExit(CyberBriefScraper().run())
