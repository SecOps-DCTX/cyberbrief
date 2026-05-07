#!/usr/bin/env python3
"""
CyberBrief Daily Data Scraper — Production Implementation

Fetches cybersecurity intelligence from multiple sources daily:
- SecurityWeek RSS
- BleepingComputer RSS
- Dark Reading RSS
- The Hacker News RSS
- CISA KEV JSON API

Extracts real article URLs from RSS feeds and scores by severity/impact.
Stores 10 per section in data.json with proper source attribution.
"""

import json
import os
import subprocess
import requests
import feedparser
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# RSS Feed URLs
FEEDS = {
    'securityweek': 'https://www.securityweek.com/feed/',
    'bleepingcomputer': 'https://www.bleepingcomputer.com/feed/',
    'darkreading': 'https://www.darkreading.com/rss.xml',
    'hackernews': 'https://thehackernews.com/feeds/posts/default'
}

# CISA KEV API
CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

class CyberBriefScraper:
    """Production scraper for daily cybersecurity intelligence."""
    
    def __init__(self):
        self.data = {'breach': [], 'cve': [], 'threat': [], 'news': []}
        self.cisa_kev = {}
    
    def fetch_cisa_kev(self):
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        logger.info("Fetching CISA KEV...")
        try:
            resp = requests.get(CISA_KEV_URL, timeout=10)
            resp.raise_for_status()
            kev_data = resp.json()
            
            for vuln in kev_data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID')
                self.cisa_kev[cve_id] = vuln
            
            logger.info(f"Loaded {len(self.cisa_kev)} KEV entries")
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV: {e}")
    
    def validate_url(self, url: str, timeout: int = 5) -> bool:
        """Check if URL is alive and valid."""
        if not url or not url.startswith('http'):
            return False
        
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True, stream=True)
            return 200 <= resp.status_code < 400
        except requests.exceptions.RequestException as e:
            logger.debug(f"URL validation failed for {url}: {e}")
            return False
    
    def fetch_rss_feeds(self):
        """Fetch and parse RSS feeds from security news sources."""
        logger.info("Fetching RSS feeds...")
        
        articles = []
        cutoff = datetime.now() - timedelta(hours=24)
        
        for source_name, feed_url in FEEDS.items():
            try:
                logger.info(f"  Fetching {source_name}...")
                feed = feedparser.parse(feed_url)
                
                for entry in feed.entries[:50]:
                    try:
                        published = datetime(*entry.published_parsed[:6]) if hasattr(entry, 'published_parsed') else datetime.now()
                        
                        if published < cutoff:
                            continue
                        
                        link = entry.get('link', '')
                        if not link or not link.startswith('http'):
                            logger.debug(f"No valid link for entry from {source_name}")
                            continue
                        
                        article = {
                            'source': source_name,
                            'title': entry.get('title', ''),
                            'summary': entry.get('summary', '')[:500],
                            'link': link,
                            'published': published.isoformat(),
                            'tags': [tag.get('term', '') for tag in entry.get('tags', [])]
                        }
                        articles.append(article)
                    except Exception as e:
                        logger.debug(f"Error parsing entry from {source_name}: {e}")
                
                count = len([a for a in articles if a['source'] == source_name])
                logger.info(f"  Got {count} recent articles from {source_name}")
            
            except Exception as e:
                logger.error(f"Error fetching {source_name}: {e}")
        
        return articles
    
    def classify_article(self, article: Dict) -> Dict[str, Any]:
        """Classify article as breach/CVE/threat/news based on content."""
        title = (article['title'] or '').lower()
        summary = (article['summary'] or '').lower()
        text = f"{title} {summary}"
        
        score = 0
        section = 'news'
        severity = 'Info'
        
        # BREACH detection
        breach_keywords = ['breach', 'data breach', 'leaked', 'compromised', 'ransomware', 'hack', 'exfiltrat']
        if any(kw in text for kw in breach_keywords):
            section = 'breach'
            score += 50
            critical_orgs = ['bank', 'financial', 'healthcare', 'government', 'military', 'health', 'hospital']
            large_breach_keywords = ['million', 'billion', 'customer', 'employee', 'patient', 'record']
            
            if any(org in text for org in critical_orgs):
                score += 20
                severity = 'Critical'
            elif any(kw in text for kw in large_breach_keywords):
                score += 10
                severity = 'High'
            else:
                severity = 'Medium'
        
        # CVE detection
        cve_keywords = ['cve-', 'vulnerability', 'zero-day', 'patch', 'exploit', 'rce', 'privesc']
        if any(kw in text for kw in cve_keywords):
            section = 'cve'
            score += 60
            
            cve_match = re.search(r'cve-\d{4}-\d+', text)
            if cve_match:
                cve_id = cve_match.group(0).upper()
                score += 10
                
                if cve_id in self.cisa_kev:
                    score += 30
                    severity = 'Critical'
                elif 'exploit' in text or 'zero-day' in text:
                    severity = 'Critical'
                elif 'patch' in text or 'available' in text:
                    severity = 'High'
                else:
                    severity = 'Medium'
            else:
                severity = 'Medium'
        
        # THREAT actor detection
        threat_keywords = ['apt', 'threat actor', 'group', 'campaign', 'ransomware gang', 'hacker', 'state-sponsor']
        threat_names = ['apt28', 'apt29', 'lazarus', 'hive0163', 'scattered spider', 'lapsus', 'alphv', 'lockbit', 'clop']
        if any(kw in text for kw in threat_keywords) or any(name in text for name in threat_names):
            section = 'threat'
            score += 55
            severity = 'High'
        
        # NEWS (regulatory, industry)
        news_keywords = ['regulation', 'law enforcement', 'fbi', 'cisa', 'policy', 'industry', 'alert', 'advisory']
        if any(kw in text for kw in news_keywords):
            section = 'news'
            score += 30
            severity = 'Info'
        
        authority_boost = {
            'securityweek': 15,
            'bleepingcomputer': 15,
            'darkreading': 12,
            'hackernews': 10
        }
        score += authority_boost.get(article['source'], 5)
        
        return {
            'section': section,
            'severity': severity,
            'score': min(score, 100),
            'article': article
        }
    
    def parse_breach(self, classified: Dict) -> Dict[str, Any]:
        """Extract structured breach data from article."""
        article = classified['article']
        title = article['title']
        
        # Extract org name from title (first 1-3 words typically)
        words = title.split()
        org = ' '.join(words[:min(3, len(words))]) if words else 'Unknown'
        
        return {
            'org': org[:50],
            'severity': classified['severity'],
            'date': datetime.now().strftime('%b %Y'),
            'records': 'See source',
            'summary': article['summary'],
            'sources': [{
                'label': article['source'].replace('_', ' ').title(),
                'url': article['link']
            }]
        }
    
    def parse_cve(self, classified: Dict) -> Dict[str, Any]:
        """Extract structured CVE data from article."""
        article = classified['article']
        text = f"{article['title']} {article['summary']}"
        
        # Extract CVE ID
        cve_match = re.search(r'(cve-\d{4}-\d+)', text, re.I)
        cve_id = cve_match.group(0).upper() if cve_match else 'CVE-XXXX-XXXXX'
        
        # Extract product name (usually 2-3 words after CVE mention)
        cve_words = text.split()
        product_name = 'Unknown Product'
        if cve_match:
            idx = text.lower().find(cve_match.group(0).lower())
            after_cve = text[idx:].split()[:5]
            product_name = ' '.join(after_cve[1:4]) if len(after_cve) > 1 else 'Unknown Product'
        
        # Try to get vendor from CISA KEV
        kev_info = self.cisa_kev.get(cve_id, {})
        vendor = kev_info.get('vendorProject', 'Unknown')
        
        return {
            'cve_id': cve_id,
            'product': product_name[:50],
            'vendor': vendor[:50],
            'severity': classified['severity'],
            'cvss': str(kev_info.get('cvssV3Score', '0')),
            'patch_status': 'See source',
            'summary': article['summary'],
            'sources': [{
                'label': article['source'].replace('_', ' ').title(),
                'url': article['link']
            }]
        }
    
    def parse_threat(self, classified: Dict) -> Dict[str, Any]:
        """Extract structured threat actor data from article."""
        article = classified['article']
        text = f"{article['title']} {article['summary']}"
        
        # Extract threat actor name
        threat_patterns = r'(apt\d+|[\w\s]+(?:group|gang|actor))'
        threat_match = re.search(threat_patterns, text, re.I)
        actor = threat_match.group(0) if threat_match else 'Unknown Actor'
        
        actor_type = 'Nation-state' if any(apt in actor.lower() for apt in ['apt', 'dprk', 'russia', 'china']) else 'Cybercrime'
        
        return {
            'actor': actor[:80],
            'type': actor_type,
            'targets': 'See source',
            'ttp': 'See source',
            'iocs': [],
            'summary': article['summary'],
            'sources': [{
                'label': article['source'].replace('_', ' ').title(),
                'url': article['link']
            }]
        }
    
    def parse_news(self, classified: Dict) -> Dict[str, Any]:
        """Extract structured news data from article."""
        article = classified['article']
        text = article['summary'].lower()
        
        # Categorize news
        category = 'News'
        if 'regulation' in text or 'sec' in text or 'fcc' in text:
            category = 'Regulatory'
        elif 'fbi' in text or 'law enforcement' in text or 'indictment' in text:
            category = 'Law Enforcement'
        elif 'patch' in text or 'vulnerability' in text or 'cve' in text:
            category = 'Vulnerability'
        elif 'industry' in text or 'trend' in text:
            category = 'Industry'
        
        return {
            'title': article['title'],
            'category': category,
            'source': article['source'].replace('_', ' ').title(),
            'date': datetime.now().strftime('%b %d, %Y'),
            'summary': article['summary'],
            'sources': [{
                'label': article['source'].replace('_', ' ').title(),
                'url': article['link']
            }]
        }
    
    def run(self, max_per_section: int = 10):
        """Execute full scrape → classify → parse → save pipeline."""
        logger.info("=" * 60)
        logger.info("CyberBrief Daily Scraper Started")
        logger.info("=" * 60)
        
        try:
            self.fetch_cisa_kev()
            articles = self.fetch_rss_feeds()
            logger.info(f"Fetched {len(articles)} articles total")
            
            if not articles:
                logger.warning("No articles found. Skipping update.")
                return False
            
            # Classify and score all articles
            classified = [self.classify_article(a) for a in articles]
            classified.sort(key=lambda x: x['score'], reverse=True)
            
            logger.info(f"Classified: {len([c for c in classified if c['section'] == 'breach'])} breaches, "
                       f"{len([c for c in classified if c['section'] == 'cve'])} CVEs, "
                       f"{len([c for c in classified if c['section'] == 'threat'])} threats, "
                       f"{len([c for c in classified if c['section'] == 'news'])} news")
            
            # Parse top items for each section
            for item in classified:
                section = item['section']
                
                if section == 'breach' and len(self.data['breach']) < max_per_section:
                    self.data['breach'].append(self.parse_breach(item))
                
                elif section == 'cve' and len(self.data['cve']) < max_per_section:
                    self.data['cve'].append(self.parse_cve(item))
                
                elif section == 'threat' and len(self.data['threat']) < max_per_section:
                    self.data['threat'].append(self.parse_threat(item))
                
                elif section == 'news' and len(self.data['news']) < max_per_section:
                    self.data['news'].append(self.parse_news(item))
            
            self.save_data()
            self.commit_to_github()
            
            logger.info("=" * 60)
            logger.info("CyberBrief Daily Scraper Completed Successfully")
            logger.info(f"Data: {len(self.data['breach'])} breaches, {len(self.data['cve'])} CVEs, "
                       f"{len(self.data['threat'])} threats, {len(self.data['news'])} news")
            logger.info("=" * 60)
            return True
        
        except Exception as e:
            logger.error(f"Pipeline failed: {e}", exc_info=True)
            return False
    
    def save_data(self, filepath: str = 'data.json'):
        """Save compiled data to JSON."""
        logger.info(f"Saving data to {filepath}...")
        try:
            with open(filepath, 'w') as f:
                json.dump(self.data, f, indent=2)
            
            logger.info(f"Saved successfully")
        except Exception as e:
            logger.error(f"Error saving data: {e}")
            raise
    
    def commit_to_github(self):
        """Commit data.json to GitHub."""
        logger.info("Committing to GitHub...")
        try:
            subprocess.run(['git', 'add', 'data.json'], check=True, capture_output=True)
            today = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            subprocess.run(['git', 'commit', '-m', f'CyberBrief data refresh — {today}'], 
                          check=True, capture_output=True)
            subprocess.run(['git', 'push', 'origin', 'main'], check=True, capture_output=True)
            logger.info(f"Pushed to GitHub")
        except subprocess.CalledProcessError as e:
            logger.debug(f"Git commit/push: {e}")

def main():
    scraper = CyberBriefScraper()
    success = scraper.run()
    exit(0 if success else 1)

if __name__ == '__main__':
    main()
