# elastic_rule_processor.py
"""
Elastic Detection Rule Processor
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Set

import boto3

from saint_datamodel import db_session, RuleRepository
from saint_datamodel.models import RuleSource, DetectionRule
from saint_datamodel.utils import generate_rule_hash, normalize_metadata

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')

class ElasticRuleProcessor:
    SOURCE_NAME = "Elastic"

    # Platform mappings
    PLATFORM_KEYWORDS = {
        "aws": "AWS",
        "azure": "Azure", 
        "gcp": "GCP",
        "oci": "OCI",
        "windows": "Windows",
        "linux": "Linux",
        "macos": "macOS",
        "kubernetes": "Containers",
        "o365": "Office 365",
        "office": "Office 365"
    }
    
    # Data source mappings from Elastic index patterns
    INDEX_TO_DATA_SOURCE = {
        "cloudtrail": "AWS CloudTrail",
        "guard-duty": "AWS GuardDuty",
        "vpcflow": "AWS VPC Flow Logs",
        "azureactivity": "Azure Activity Logs",
        "gcpaudit": "GCP Audit Logs",
        "winlogbeat": "Windows Event Logs",
        "filebeat": "System Logs",
        "packetbeat": "Network Traffic",
        "auditbeat": "Linux Audit Logs"
    }

    def __init__(self):
        self.processed_count = 0
        self.created_count = 0
        self.updated_count = 0
        self.skipped_count = 0
        self.error_count = 0
        self.skipped_lines = 0
        self.processed_rule_ids = []
        self.siem_platform = None  # Will be set from S3 path

    def get_or_create_source(self, session, source_name: str = None) -> RuleSource:
        """Gets or creates the RuleSource based on SIEM platform"""
        # Use provided source name or fall back to default
        name = source_name or self.SOURCE_NAME
        
        source = session.query(RuleSource).filter_by(name=name).first()
        if source:
            return source
            
        logger.info(f"Rule source '{name}' not found, creating it.")
        new_source = RuleSource(
            name=name,
            description=f"Detection rules imported from {name} SIEM.",
            source_type="SIEM",
            base_url=os.environ.get('KIBANA_URL'),
            is_active=True,
            source_metadata={'siem_platform': name}
        )
        session.add(new_source)
        session.flush()
        return new_source

    def _extract_platforms_from_tags(self, tags: List[str]) -> List[str]:
        """Extracts and normalizes platform names from tags"""
        platforms: Set[str] = set()
        for tag in tags:
            tag_lower = tag.lower()
            for keyword, platform_name in self.PLATFORM_KEYWORDS.items():
                if keyword in tag_lower:
                    platforms.add(platform_name)
        return sorted(list(platforms))
    
    def _extract_data_sources(self, rule_json: Dict[str, Any]) -> List[str]:
        """Extract data sources from rule indices"""
        data_sources = set()
        indices = rule_json.get('index', [])
        
        for index in indices:
            index_lower = index.lower()
            for pattern, source_name in self.INDEX_TO_DATA_SOURCE.items():
                if pattern in index_lower:
                    data_sources.add(source_name)
        
        return sorted(list(data_sources))
    
    def _extract_info_controls(self, rule_json: Dict[str, Any]) -> Optional[str]:
        """Extract information control markings from rule metadata or tags"""
        # Check rule note or description for markings
        note = rule_json.get('note', '')
        description = rule_json.get('description', '')
        tags = rule_json.get('tags', [])
        
        # Common patterns for info controls
        patterns = [
            r'CUI[/\\]{1,2}[A-Z]+',
            r'TLP:\s?\w+',
            r'PROPIN\b',
            r'NOFORN\b',
            r'REL\s?TO\s?[A-Z,\s]+',
            r'U[/\\]{1,2}FOUO'
        ]
        
        combined_text = f"{note} {description} {' '.join(tags)}"
        
        for pattern in patterns:
            match = re.search(pattern, combined_text, re.IGNORECASE)
            if match:
                return match.group(0).upper()
        
        return None
    
    def _extract_aor(self, rule_json: Dict[str, Any]) -> Optional[str]:
        """Extract Area of Responsibility from rule metadata"""
        meta = rule_json.get('meta', {})
        tags = rule_json.get('tags', [])
        
        # Check meta field for deployment info
        if 'kibana_siem_app_url' in meta:
            url = meta['kibana_siem_app_url']
            if 'aws' in url.lower():
                return "AWS Cloud"
            elif 'azure' in url.lower():
                return "Azure Cloud"
            elif 'gcp' in url.lower() or 'google' in url.lower():
                return "Google Cloud"
            elif 'onprem' in url.lower() or 'datacenter' in url.lower():
                return "Datacenter"
        
        # Check tags for AOR indicators
        for tag in tags:
            tag_lower = tag.lower()
            if 'aws' in tag_lower:
                return "AWS Cloud"
            elif 'azure' in tag_lower:
                return "Azure Cloud"
            elif 'gcp' in tag_lower:
                return "Google Cloud"
            elif 'enclave' in tag_lower:
                return "Enclave"
            elif 'bcap' in tag_lower:
                return "BCAP"
            elif 'iap' in tag_lower:
                return "IAP"
        
        return None

    def _validate_rule_structure(self, rule_json: Dict[str, Any]) -> bool:
        """Validate that the rule has required fields."""
        required_fields = ['rule_id', 'name']
        
        for field in required_fields:
            if field not in rule_json:
                logger.warning(f"Rule missing required field '{field}': {rule_json.get('rule_id', 'unknown')}")
                return False
        
        return True

    def _build_rule_metadata(self, rule_json: Dict[str, Any], platforms: List[str]) -> Dict[str, Any]:
        """Build comprehensive rule metadata including new required fields"""
        
        # Extract author information
        author = rule_json.get('author', [])
        if isinstance(author, list):
            author = ', '.join(author) if author else None
        
        # Build metadata structure
        metadata = {
            # Existing fields
            'rule_platforms': platforms,
            'rule_version': rule_json.get('version'),
            'rule_enabled': rule_json.get('enabled', True),
            'rule_risk_score': rule_json.get('risk_score'),
            'rule_max_signals': rule_json.get('max_signals'),
            'source_type': 'elastic',
            'needs_enrichment': True,
            'processor_version': '3.0',
            'original_tags_count': len(rule_json.get('tags', [])),
            'threat_mapping_present': bool(rule_json.get('threat')),
            
            # Core metadata fields
            'author': author,
            'language': rule_json.get('language', 'kusto').lower(),
            'index': rule_json.get('index', []),
            'references': rule_json.get('references', []),
            
            # New required metadata fields
            'info_controls': self._extract_info_controls(rule_json),
            'siem_platform': self.siem_platform or 'Elastic Security',  # Use extracted platform name
            'aor': self._extract_aor(rule_json),
            'source_org': rule_json.get('author', [None])[0] if rule_json.get('author') else None,
            'data_sources': self._extract_data_sources(rule_json),
            'modified_by': rule_json.get('updated_by'),
            'hunt_id': None,  # Will be extracted during enrichment if present in note
            'malware_family': None,  # Will be extracted during enrichment
            'intrusion_set': None,  # Will be extracted during enrichment
            'cwe_ids': [],  # Will be populated during enrichment
            'validation': {
                'testable_via': None,
                'asv_action_id': None,
                'validated': False,
                'last_tested': rule_json.get('last_tested')
            }
        }
        
        # Extract hunt ID from note if present
        note = rule_json.get('note', '')
        hunt_match = re.search(r'HUNT-\d{4}-\d{3,}', note, re.IGNORECASE)
        if hunt_match:
            metadata['hunt_id'] = hunt_match.group(0).upper()
        
        # Check for malware family in tags or description
        malware_patterns = [
            'emotet', 'trickbot', 'cobalt strike', 'lazarus', 'apt28', 'apt29',
            'fin7', 'carbanak', 'darkside', 'revil', 'conti', 'lockbit'
        ]
        
        combined_text = f"{rule_json.get('description', '')} {' '.join(rule_json.get('tags', []))}".lower()
        for pattern in malware_patterns:
            if pattern in combined_text:
                metadata['malware_family'] = pattern.title()
                break
        
        return metadata

    def _build_basic_tags(self, rule_json: Dict[str, Any], platforms: List[str]) -> List[str]:
        """Build basic tags for the rule"""
        basic_tags = ["source:elastic"]
        
        # Add SIEM platform tag
        if self.siem_platform:
            basic_tags.append(f"siem:{self.siem_platform}")
        
        # Add platform tags
        for platform in platforms:
            basic_tags.append(f"platform:{platform.lower()}")
        
        # Add rule type info
        rule_type = rule_json.get('type', 'query')
        basic_tags.append(f"rule_type:{rule_type}")
        
        # Add severity
        severity = rule_json.get('severity', 'medium')
        basic_tags.append(f"severity:{severity}")
        
        # Add first few original tags
        original_tags = rule_json.get('tags', [])[:5]
        for tag in original_tags:
            if isinstance(tag, str) and len(tag) < 50:
                basic_tags.append(f"elastic_tag:{tag.lower()}")
        
        return basic_tags

    def _map_and_upsert_rule(self, rule_json: Dict[str, Any], rule_repo: RuleRepository, source_id: int) -> Optional[DetectionRule]:
        """Map Elastic rule to DetectionRule model and upsert"""
        
        # Validate rule structure
        if not self._validate_rule_structure(rule_json):
            return None
        
        rule_id = rule_json.get('rule_id')
        
        # Store the original JSON as rule content
        rule_content = json.dumps(rule_json, sort_keys=True)
        rule_hash = generate_rule_hash(rule_content)

        # Extract platforms and build metadata
        tags = rule_json.get('tags', [])
        platforms = self._extract_platforms_from_tags(tags)
        rule_metadata = self._build_rule_metadata(rule_json, platforms)
        basic_tags = self._build_basic_tags(rule_json, platforms)

        rule_payload = {
            'name': rule_json.get('name'),
            'description': rule_json.get('description', ''),
            'rule_content': rule_content,
            'rule_type': rule_json.get('type', 'query'),
            'severity': rule_json.get('severity', 'medium'),
            'is_active': rule_json.get('enabled', True),
            'tags': basic_tags,
            'rule_metadata': normalize_metadata(rule_metadata)
        }

        # First check if rule exists for THIS source by rule_id
        existing_rule = rule_repo.get_by_source_and_rule_id(source_id, rule_id)
        
        if existing_rule:
            # Update existing rule if content has changed
            if existing_rule.hash != rule_hash:
                for key, value in rule_payload.items():
                    setattr(existing_rule, key, value)
                existing_rule.hash = rule_hash
                self.updated_count += 1
                logger.info(f"Updated rule: {rule_id} for source {source_id}")
                return existing_rule
            else:
                self.skipped_count += 1
                logger.debug(f"Rule unchanged: {rule_id}")
                return existing_rule
        else:
            # Check if same content exists globally (different source)
            existing_by_hash = rule_repo.session.query(DetectionRule).filter(
                DetectionRule.hash == rule_hash
            ).first()
            
            if existing_by_hash:
                # Same rule content exists but for different source
                # Create a new entry with same content but different source
                logger.info(f"Rule content exists in another source, creating duplicate for source {source_id}")
                
                # Modify hash slightly to make it unique per source
                # Append source_id to rule_content for hash generation
                source_specific_content = rule_content + f"_source_{source_id}"
                source_specific_hash = generate_rule_hash(source_specific_content)
                
                rule_payload['rule_id'] = rule_id
                rule_payload['source_id'] = source_id
                rule_payload['hash'] = source_specific_hash
                
                new_rule = DetectionRule(**rule_payload)
                rule_repo.session.add(new_rule)
                rule_repo.session.flush()
                self.created_count += 1
                logger.info(f"Created rule variant: {rule_id} for source {source_id}")
                return new_rule
            else:
                # Completely new rule
                rule_payload['rule_id'] = rule_id
                rule_payload['source_id'] = source_id
                rule_payload['hash'] = rule_hash
                
                new_rule = DetectionRule(**rule_payload)
                rule_repo.session.add(new_rule)
                rule_repo.session.flush()
                self.created_count += 1
                logger.info(f"Created new rule: {rule_id}")
                return new_rule

    def process_s3_object(self, bucket: str, key: str):
        """Process an Elastic rules file from S3"""
        logger.info(f"Processing S3 object: s3://{bucket}/{key}")
        
        # Extract SIEM platform from S3 key path
        # Expected format: gms-elastic/file.ndjson or td-elastic/file.ndjson
        try:
            folder_name = key.split('/')[0]
            if folder_name in ['gms-elastic', 'td-elastic']:
                self.siem_platform = folder_name
                source_name = folder_name.upper()
            else:
                # Fallback for unexpected folder structure
                self.siem_platform = 'Elastic Security'
                source_name = self.SOURCE_NAME
                logger.warning(f"Unexpected folder structure: {folder_name}, using default SIEM platform name")
        except (IndexError, AttributeError):
            self.siem_platform = 'Elastic Security'
            source_name = self.SOURCE_NAME
            logger.warning(f"Could not extract SIEM platform from key: {key}")
        
        logger.info(f"Using SIEM platform: {self.siem_platform}, Source: {source_name}")
        
        try:
            s3_object = s3_client.get_object(Bucket=bucket, Key=key)
            file_content = s3_object['Body'].read().decode('utf-8')
            
            # Process NDJSON format
            rules = []
            for line in file_content.strip().split('\n'):
                if line:
                    try:
                        rule_json = json.loads(line)
                        rules.append(rule_json)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON line: {e}")
                        self.skipped_lines += 1
            
            logger.info(f"Found {len(rules)} rules to process")
            
            with db_session() as session:
                rule_repo = RuleRepository(session)
                source = self.get_or_create_source(session, source_name)
                
                for rule_json in rules:
                    self.processed_count += 1
                    try:
                        db_rule = self._map_and_upsert_rule(rule_json, rule_repo, source.id)
                        if db_rule:
                            self.processed_rule_ids.append(db_rule.rule_id)
                    except Exception as e:
                        self.error_count += 1
                        logger.error(f"Failed to process rule {rule_json.get('rule_id')}: {e}", exc_info=True)
                
                session.commit()
                
        except Exception as e:
            self.error_count += 1
            logger.error(f"Fatal error processing S3 object: {e}", exc_info=True)
        
        logger.info(
            f"Processing complete. Processed: {self.processed_count}, Created: {self.created_count}, "
            f"Updated: {self.updated_count}, Skipped: {self.skipped_count}, Errors: {self.error_count}"
        )

def lambda_handler(event, context):
    """Lambda handler for processing Elastic rules from S3"""
    processor = ElasticRuleProcessor()
    
    for record in event.get('Records', []):
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        
        # Process files from both gms-elastic and td-elastic folders
        if key.startswith('gms-elastic/') or key.startswith('td-elastic/'):
            processor.process_s3_object(bucket, key)
        else:
            logger.warning(f"Skipping file not in expected folders: {key}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Elastic rule processing complete',
            'siem_platform': processor.siem_platform,
            'processed': processor.processed_count,
            'created': processor.created_count,
            'updated': processor.updated_count,
            'skipped': processor.skipped_count,
            'errors': processor.error_count
        })
    }