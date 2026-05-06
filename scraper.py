#!/usr/bin/env python3
"""
CyberBrief Daily Data Scraper — Production Implementation

Fetches cybersecurity intelligence from multiple sources daily:
- SecurityWeek RSS
- BleepingComputer RSS
- Dark Reading RSS
- CISA KEV JSON API
- The Hacker News RSS

Scores items by severity/impact and stores 10-20 per day in data.json.
"""

import json
import os
import subprocess
import requests
import feedparser
from datetime import datetime, timedelta
from typing import Dict, List, Any
from bs4 import BeautifulSoup
import logging

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
        self.cisa_kev = {}  # Cache of CISA KEV data
    
    def fetch_cisa_kev(self):
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        logger.info("Fetching CISA KEV...")
        try:
            resp = requests.get(CISA_KEV_URL, timeout=10)
            resp.raise_for_status()
            kev_data = resp.json()
            
            # Build a lookup table: CVE ID -> KEV details
            for vuln in kev_data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID')
                self.cisa_kev[cve_id] = vuln
            
            logger.info(f"Loaded {len(self.cisa_kev)} KEV entries")
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV: {e}")
    
    def fetch_rss_feeds(self):
        """Fetch and parse RSS feeds from security news sources."""
        logger.info("Fetching RSS feeds...")
        
        articles = []
        
        for source_name, feed_url in FEEDS.items():
            try:
                logger.info(f"  Fetching {source_name}...")
                feed = feedparser.parse(feed_url)
                
                # Get entries from the last 24 hours
                cutoff = datetime.now() - timedelta(hours=24)
                
                for entry in feed.entries[:50]:  # Limit to recent entries
                    try:
                        published = datetime(*entry.published_parsed[:6]) if hasattr(entry, 'published_parsed') else datetime.now()
                        
                        if published < cutoff:
                            continue
                        
                        article = {
                            'source': source_name,
                            'title': entry.get('title', ''),
                            'summary': entry.get('summary', '')[:500],  # Truncate
                            'link': entry.get('link', ''),
                            'published': published.isoformat(),
                            'tags': [tag.get('term', '') for tag in entry.get('tags', [])]
                        }
                        articles.append(article)
                    except Exception as e:
                        logger.debug(f"Error parsing entry from {source_name}: {e}")
                
                logger.info(f"  Got {len([a for a in articles if a['source'] == source_name])} recent articles from {source_name}")
            
            except Exception as e:
                logger.error(f"Error fetching {source_name}: {e}")
        
        return articles
    
    def classify_article(self, article: Dict) -> Dict[str, Any]:
        """
        Classify an article as breach/CVE/threat/news based on content.
        
        Returns a dict with:
        - section: 'breach' | 'cve' | 'threat' | 'news'
        - severity: 'Critical' | 'High' | 'Medium' | 'Info'
        - score: 0-100 (higher = more important)
        - structured_data: parsed fields specific to the section
        """
        title = (article['title'] or '').lower()
        summary = (article['summary'] or '').lower()
        text = f"{title} {summary}"
        
        score = 0
        section = 'news'  # Default
        severity = 'Info'
        
        # === BREACH detection ===
        breach_keywords = ['breach', 'data breach', 'leaked', 'compromised', 'ransomware', 'hack']
        if any(kw in text for kw in breach_keywords):
            section = 'breach'
            score += 50
            
            # Severity boost for large breaches or critical orgs
            critical_orgs = ['bank', 'financial', 'healthcare', 'government', 'military']
            large_breach_keywords = ['million', 'billion', 'customer', 'employee']
            
            if any(org in text for org in critical_orgs):
                score += 20
                severity = 'Critical'
            elif any(kw in text for kw in large_breach_keywords):
                score += 10
                severity = 'High'
            else:
                severity = 'Medium'
        
        # === CVE detection ===
        cve_keywords = ['cve-', 'vulnerability', 'zero-day', 'patch', 'exploit', 'rce', 'privesc']
        if any(kw in text for kw in cve_keywords):
            section = 'cve'
            score += 60
            
            # Look for CVE IDs
            import re
            cve_match = re.search(r'cve-\d{4}-\d+', text)
            if cve_match:
                cve_id = cve_match.group(0).upper()
                score += 10
                
                # Check if it's in CISA KEV
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
        
        # === THREAT actor detection ===
        threat_keywords = ['apt', 'threat actor', 'group', 'campaign', 'ransomware gang', 'hacker']
        threat_names = ['apt28', 'apt29', 'lazarus', 'hive0163', 'scattered spider', 'lapsus']
        if any(kw in text for kw in threat_keywords) or any(name in text for name in threat_names):
            section = 'threat'
            score += 55
            severity = 'High'
        
        # === NEWS (regulatory, industry) ===
        news_keywords = ['regulation', 'law enforcement', 'fbi', 'cisa', 'policy', 'industry', 'alert']
        if any(kw in text for kw in news_keywords):
            section = 'news'
            score += 30
            severity = 'Info'
        
        # Boost score if from authoritative source
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
        
        # Extract org name (usually first part of title)
        org = title.split(' ')[0] if title else 'Unknown'
        
        return {
            'org': org,
            'severity': classified['severity'],
            'date': datetime.now().strftime('%b %Y'),
            'records': 'Unknown',
            'summary': article['summary'],
            'sources': [{'label': article['source'].replace('_', ' ').title(), 'url': article['link']}]
        }
    
    def parse_cve(self, classified: Dict) -> Dict[str, Any]:
        """Extract structured CVE data from article."""
        import re
        article = classified['article']
        text = f"{article['title']} {article['summary']}"
        
        cve_match = re.search(r'(cve-\d{4}-\d+)', text, re.I)
        cve_id = cve_match.group(0).upper() if cve_match else 'CVE-2026-00000'
        
        product = text.split(' ')[2:5]  # Rough extraction
        product_name = ' '.join(product) if product else 'Unknown Product'
        
        kev_info = self.cisa_kev.get(cve_id, {})
        
        return {
            'cve_id': cve_id,
            'product': product_name[:50],
            'vendor': kev_info.get('vendorProject', 'Unknown'),
            'severity': classified['severity'],
            'cvss': kev_info.get('cvssV3Score', '0'),
            'patch_status': 'Status unknown',
            'summary': article['summary'],
            'sources': [{'label': article['source'].replace('_', ' ').title(), 'url': article['link']}]
        }
    
    def parse_threat(self, classified: Dict) -> Dict[str, Any]:
        """Extract structured threat actor data from article."""
        import re
        article = classified['article']
        text = f"{article['title']} {article['summary']}"
        
        # Extract threat actor name
        threat_patterns = r'(apt\d+|[\w\s]+(?:group|gang|actor))'
        threat_match = re.search(threat_patterns, text, re.I)
        actor = threat_match.group(0) if threat_match else 'Unknown Actor'
        
        return {
            'actor': actor,
            'type': 'Nation-state' if 'apt' in text.lower() else 'Cybercrime',
            'targets': 'Multiple sectors',
            'ttp': 'See article for details',
            'iocs': [],
            'summary': article['summary'],
            'sources': [{'label': article['source'].replace('_', ' ').title(), 'url': article['link']}]
        }
    
    def parse_news(self, classified: Dict) -> Dict[str, Any]:
        """Extract structured news data from article."""
        article = classified['article']
        
        category_map = {
            'regulation': 'Regulatory',
            'fbi': 'Law Enforcement',
            'cisa': 'Regulatory',
            'patch': 'Vulnerability',
            'industry': 'Industry'
        }
        
        category = 'News'
        for keyword, cat in category_map.items():
            if keyword in article['summary'].lower():
                category = cat
                break
        
        return {
            'title': article['title'],
            'category': category,
            'source': article['source'].replace('_', ' ').title(),
            'date': datetime.now().strftime('%b %d, %Y'),
            'summary': article['summary'],
            'sources': [{'label': article['source'].replace('_', ' ').title(), 'url': article['link']}]
        }
    
    def run(self, max_per_section: int = 10):
        """Execute full scrape → classify → parse → save pipeline."""
        logger.info("=" * 60)
        logger.info("CyberBrief Daily Scraper Started")
        logger.info("=" * 60)
        
        try:
            # 1. Fetch CISA KEV for context
            self.fetch_cisa_kev()
            
            # 2. Fetch all RSS articles
            articles = self.fetch_rss_feeds()
            logger.info(f"Fetched {len(articles)} articles total")
            
            if not articles:
                logger.warning("No articles found. Using fallback data.")
                return False
            
            # 3. Classify and score each article
            classified = [self.classify_article(a) for a in articles]
            classified.sort(key=lambda x: x['score'], reverse=True)
            
            # 4. Parse into structured sections
            for item in classified[:max_per_section * 2]:  # Process 2x to have buffer
                section = item['section']
                
                if section == 'breach':
                    parsed = self.parse_breach(item)
                    if len(self.data['breach']) < max_per_section:
                        self.data['breach'].append(parsed)
                
                elif section == 'cve':
                    parsed = self.parse_cve(item)
                    if len(self.data['cve']) < max_per_section:
                        self.data['cve'].append(parsed)
                
                elif section == 'threat':
                    parsed = self.parse_threat(item)
                    if len(self.data['threat']) < max_per_section:
                        self.data['threat'].append(parsed)
                
                elif section == 'news':
                    parsed = self.parse_news(item)
                    if len(self.data['news']) < max_per_section:
                        self.data['news'].append(parsed)
            
            # 5. Save to data.json
            self.save_data()
            
            # 6. Commit to GitHub
            self.commit_to_github()
            
            logger.info("=" * 60)
            logger.info("CyberBrief Daily Scraper Completed Successfully")
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
            
            logger.info(f"Saved: {len(self.data['breach'])} breaches, {len(self.data['cve'])} CVEs, "
                       f"{len(self.data['threat'])} threats, {len(self.data['news'])} news")
        except Exception as e:
            logger.error(f"Error saving data: {e}")
            raise
    
    def commit_to_github(self):
        """Commit data.json to GitHub."""
        logger.info("Committing to GitHub...")
        try:
            result = subprocess.run(['git', 'diff', '--quiet', 'data.json'], capture_output=True, check=False)
            
            if result.returncode != 0:  # File changed
                subprocess.run(['git', 'add', 'data.json'], check=True)
                today = datetime.now().strftime('%Y-%m-%d')
                subprocess.run(['git', 'commit', '-m', f'CyberBrief daily update — {today}'], check=True, capture_output=True)
                subprocess.run(['git', 'push', 'origin', 'main'], check=True, capture_output=True)
                logger.info(f"Pushed update for {today}")
            else:
                logger.info("No changes to commit")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git error: {e}")
            raise

def main():
    scraper = CyberBriefScraper()
    success = scraper.run()
    exit(0 if success else 1)

if __name__ == '__main__':
    main()
