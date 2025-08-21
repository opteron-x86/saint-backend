# elastic_rule_processor.py
"""
Elastic Detection Rule Processor for SAINT
Processes Elastic rules and stores them in the database.
Enrichment is handled by the dedicated enrichment layer.
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

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')

class ElasticRuleProcessor:
    SOURCE_NAME = "Elastic"

    # Mapping of keywords in tags to normalized platform names
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

    def __init__(self):
        self.processed_count = 0
        self.created_count = 0
        self.updated_count = 0
        self.skipped_count = 0
        self.error_count = 0
        self.skipped_lines = 0
        self.processed_rule_ids = []

    def get_or_create_source(self, session) -> RuleSource:
        """Gets or creates the 'Elastic' RuleSource."""
        source = session.query(RuleSource).filter_by(name=self.SOURCE_NAME).first()
        if source:
            return source
        logger.info(f"Rule source '{self.SOURCE_NAME}' not found, creating it.")
        new_source = RuleSource(
            name=self.SOURCE_NAME,
            description="Detection rules imported from an Elastic SIEM export.",
            source_type="SIEM",
            base_url=os.environ.get('KIBANA_URL'),
            is_active=True
        )
        session.add(new_source)
        session.flush()
        return new_source

    def _extract_platforms_from_tags(self, tags: List[str]) -> List[str]:
        """Extracts and normalizes platform names from a list of tags"""
        platforms: Set[str] = set()
        for tag in tags:
            tag_lower = tag.lower()
            for keyword, platform_name in self.PLATFORM_KEYWORDS.items():
                if keyword in tag_lower:
                    platforms.add(platform_name)
        return sorted(list(platforms))

    def _validate_rule_structure(self, rule_json: Dict[str, Any]) -> bool:
        """Validate that the rule has required fields."""
        required_fields = ['rule_id', 'name']
        
        for field in required_fields:
            if field not in rule_json:
                logger.warning(f"Rule missing required field '{field}': {rule_json.get('rule_id', 'unknown')}")
                return False
        
        return True

    def _build_rule_metadata(self, rule_json: Dict[str, Any], platforms: List[str]) -> Dict[str, Any]:
        """Build rule metadata"""
        return {
            'rule_platforms': platforms,
            'rule_version': rule_json.get('version'),
            'rule_enabled': rule_json.get('enabled', True),
            'rule_risk_score': rule_json.get('risk_score'),
            'rule_max_signals': rule_json.get('max_signals'),
            'source_type': 'elastic',
            'needs_enrichment': True,  # Flag for enrichment layer
            'processor_version': '2.0', 
            'original_tags_count': len(rule_json.get('tags', [])),
            'threat_mapping_present': bool(rule_json.get('threat'))  # Track if rule has threat data
        }

    def _build_basic_tags(self, rule_json: Dict[str, Any], platforms: List[str]) -> List[str]:
        """Build basic tags"""
        basic_tags = ["source:elastic"]
        
        # Add platform tags
        for platform in platforms:
            basic_tags.append(f"platform:{platform.lower()}")
        
        # Add rule type info
        rule_type = rule_json.get('type', 'query')
        basic_tags.append(f"rule_type:{rule_type}")
        
        # Add severity if present
        severity = rule_json.get('severity', 'medium')
        basic_tags.append(f"severity:{severity}")
        
        # Add first few original tags (truncated to avoid bloat)
        original_tags = rule_json.get('tags', [])[:5]  # Limit to first 5
        for tag in original_tags:
            if isinstance(tag, str) and len(tag) < 50:  # Avoid very long tags
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

        # FIRST: Check if rule with same hash already exists (prevents duplicates)
        with rule_repo.session:
            existing_by_hash = rule_repo.session.query(DetectionRule).filter(
                DetectionRule.hash == rule_hash,
                DetectionRule.source_id == source_id
            ).first()
            
            if existing_by_hash:
                # Rule with same content already exists
                self.skipped_count += 1
                logger.debug(f"Skipping duplicate rule (hash exists): {rule_id} -> DB ID {existing_by_hash.id}")
                return existing_by_hash

        # Extract platforms from tags
        tags = rule_json.get('tags', [])
        platforms = self._extract_platforms_from_tags(tags)
        
        # Build metadata and tags
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

        # SECOND: Try to find by rule_id and source (normal case)
        db_rule = rule_repo.get_by_source_and_rule_id(source_id=source_id, rule_id=str(rule_id))
        
        if db_rule:
            if db_rule.hash != rule_hash:
                rule_repo.update(db_rule.id, hash=rule_hash, **rule_payload)
                self.updated_count += 1
                logger.info(f"Updated Elastic rule: {rule_id}")
            else:
                self.skipped_count += 1
                logger.debug(f"Skipping unchanged rule: {rule_id}")
            return db_rule
        else:
            # THIRD: Create new rule
            try:
                db_rule = rule_repo.create(rule_id=str(rule_id), source_id=source_id, hash=rule_hash, **rule_payload)
                self.created_count += 1
                logger.info(f"Created Elastic rule: {rule_id}")
                return db_rule
            except Exception as e:
                if "duplicate key value violates unique constraint" in str(e):
                    self.skipped_count += 1
                    logger.warning(f"Hash collision detected for rule {rule_id}, skipping")
                    return None
                else:
                    raise e

    def process_rule_line(self, rule_json: Dict[str, Any], session, source_id: int):
        """Process a single rule line from NDJSON file"""
        with session:
            rule_repo = RuleRepository(session)
            db_rule = self._map_and_upsert_rule(rule_json, rule_repo, source_id)
            
            if db_rule:
                self.processed_rule_ids.append(db_rule.id)
            
            # Commit each rule individually to prevent large transaction issues
            session.commit()

    def process_s3_object(self, bucket: str, key: str):
        """Main processing logic for the S3 file"""
        logger.info(f"Processing S3 object: s3://{bucket}/{key}")
        
        try:
            s3_object = s3_client.get_object(Bucket=bucket, Key=key)
            
            # Get Elastic source
            with db_session() as session:
                elastic_source = self.get_or_create_source(session)
                source_id = elastic_source.id
            
            # Process NDJSON file line by line
            for line_num, line in enumerate(s3_object['Body'].iter_lines(), 1):
                line_str = line.decode('utf-8').strip()
                
                # Skip empty lines
                if not line_str:
                    self.skipped_lines += 1
                    continue
                
                # Skip lines that don't look like rule JSON
                if '"rule_id":' not in line_str:
                    self.skipped_lines += 1
                    continue

                try:
                    # Parse and process rule
                    rule_json = json.loads(line_str)
                    
                    with db_session() as session:
                        self.processed_count += 1
                        self.process_rule_line(
                            rule_json=rule_json,
                            session=session,
                            source_id=source_id
                        )
                        
                except json.JSONDecodeError as e:
                    self.error_count += 1
                    logger.error(f"Invalid JSON on line {line_num}: {e}")
                except Exception as e:
                    self.error_count += 1
                    logger.error(f"Failed to process line {line_num}: {e}")

            # Trigger enrichment after successful processing
            if self.processed_rule_ids:
                self._trigger_enrichment(source_id, self.processed_rule_ids)
                
        except Exception as e:
            self.error_count += 1
            logger.error(f"Fatal error processing S3 object s3://{bucket}/{key}: {e}", exc_info=True)

        # Log final summary
        logger.info(
            f"Elastic processing finished. Rules processed: {self.processed_count}, "
            f"Created: {self.created_count}, Updated: {self.updated_count}, "
            f"Skipped: {self.skipped_count}, Lines skipped: {self.skipped_lines}, Errors: {self.error_count}"
        )

    def _trigger_enrichment(self, source_id: int, rule_ids: List[int]):
        """Trigger enrichment orchestrator for processed rules."""
        try:
            payload = {
                'source_completed': True,
                'source_id': source_id,
                'rule_ids': rule_ids,
                'source_name': self.SOURCE_NAME,
                'processor_version': '2.0'
            }
            
            response = lambda_client.invoke(
                FunctionName='saint-enrichment-orchestrator',
                InvocationType='Event',  # Async invocation
                Payload=json.dumps(payload)
            )
            
            logger.info(f"Successfully triggered enrichment for {len(rule_ids)} Elastic rules")
            
        except Exception as e:
            logger.error(f"Failed to trigger enrichment orchestrator: {e}")
            # Don't fail the entire processing if enrichment trigger fails

def lambda_handler(event: Dict[str, Any], context: object) -> Dict[str, Any]:
    """Main Lambda handler for Elastic rule processing."""
    processor = ElasticRuleProcessor()
    
    try:
        for record in event.get('Records', []):
            s3_info = record.get('s3', {})
            bucket = s3_info.get('bucket', {}).get('name')
            key = s3_info.get('object', {}).get('key')

            if not bucket or not key or not key.endswith('.ndjson'):
                logger.warning(f"Skipping invalid S3 object: bucket={bucket}, key={key}")
                continue
                
            processor.process_s3_object(bucket=bucket, key=key)

        response_body = {
            'message': 'Elastic rule processing completed.',
            'results': {
                'rules_processed': processor.processed_count,
                'rules_created': processor.created_count,
                'rules_updated': processor.updated_count,
                'rules_skipped': processor.skipped_count,
                'lines_skipped': processor.skipped_lines,
                'errors': processor.error_count,
                'enrichment_triggered': len(processor.processed_rule_ids) > 0
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return {
            'statusCode': 200 if processor.error_count == 0 else 207,
            'body': json.dumps(response_body)
        }
        
    except Exception as e:
        logger.error(f"Elastic processor failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'message': 'Elastic processing failed'
            })
        }