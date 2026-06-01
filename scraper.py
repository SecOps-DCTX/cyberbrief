#!/usr/bin/env python3
"""
CyberBrief Scraper with Item Aging & Archive System

Tracks item age (refresh count) and moves items to archive after 4 refreshes.
"""

import json
import os
from datetime import datetime
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CyberBriefScraper:
    def __init__(self):
        self.data_file = 'data.json'
        self.archive_file = 'archive.json'
        self.max_age = 4  # Archive after 4 refreshes (2 days at 2x daily schedule)
    
    def load_data(self):
        """Load current data.json"""
        if os.path.exists(self.data_file):
            with open(self.data_file, 'r') as f:
                return json.load(f)
        return {'breach': [], 'cve': [], 'threat': [], 'news': []}
    
    def load_archive(self):
        """Load archive.json"""
        if os.path.exists(self.archive_file):
            with open(self.archive_file, 'r') as f:
                return json.load(f)
        return {'breach': [], 'cve': [], 'threat': [], 'news': []}
    
    def save_data(self, data):
        """Save data.json"""
        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def save_archive(self, archive):
        """Save archive.json"""
        with open(self.archive_file, 'w') as f:
            json.dump(archive, f, indent=2)
    
    def age_items(self, data, archive):
        """Increment age and move old items to archive"""
        for section in ['breach', 'cve', 'threat', 'news']:
            if section not in data:
                continue
            
            items_to_keep = []
            for item in data[section]:
                # Initialize age if missing
                item['age'] = item.get('age', 0)
                
                # Increment age on each refresh
                item['age'] += 1
                
                if item['age'] > self.max_age:
                    # Move to archive
                    if section not in archive:
                        archive[section] = []
                    archive[section].append(item)
                    title = item.get('org') or item.get('cve_id') or item.get('actor') or item.get('title', 'Unknown')
                    logger.info(f"✓ Archived: {title} (age: {item['age']})")
                else:
                    # Keep in active data
                    items_to_keep.append(item)
            
            data[section] = items_to_keep
        
        return data, archive
    
    def run(self):
        """Main execution"""
        logger.info("="*70)
        logger.info("CyberBrief Scraper with Item Aging Started")
        logger.info(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("="*70)
        
        try:
            # Load existing data and archive
            data = self.load_data()
            archive = self.load_archive()
            
            logger.info(f"Loaded: {sum(len(data.get(s, [])) for s in ['breach','cve','threat','news'])} active items")
            logger.info(f"Archive: {sum(len(archive.get(s, [])) for s in ['breach','cve','threat','news'])} archived items")
            
            # Age items and move to archive
            data, archive = self.age_items(data, archive)
            
            # Save updated data and archive
            self.save_data(data)
            self.save_archive(archive)
            
            logger.info("✓ Data aging complete")
            logger.info(f"Active items now: {sum(len(data.get(s, [])) for s in ['breach','cve','threat','news'])}")
            logger.info(f"Archive now: {sum(len(archive.get(s, [])) for s in ['breach','cve','threat','news'])}")
            
            # Git commit
            self.commit_changes()
            
            logger.info("="*70)
            logger.info("✓ CyberBrief Update Complete")
            logger.info("="*70)
            return 0
            
        except Exception as e:
            logger.error(f"ERROR: {e}")
            logger.error("Keeping existing data files")
            return 1
    
    def commit_changes(self):
        """Commit changes to git"""
        try:
            os.system('git config user.email "cyberbrief@automation.local"')
            os.system('git config user.name "CyberBrief Scraper"')
            os.system('git add data.json archive.json')
            os.system(f'git commit -m "CyberBrief update — {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}"')
            os.system('git push origin main')
            logger.info("✓ Changes pushed to GitHub")
        except Exception as e:
            logger.warning(f"Git commit failed: {e}")

if __name__ == '__main__':
    scraper = CyberBriefScraper()
    exit_code = scraper.run()
    exit(exit_code)
