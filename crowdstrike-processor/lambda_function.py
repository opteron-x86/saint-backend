# crowdstrike_processor_simplified.py
"""
Simplified CrowdStrike Processor - Parsing and Storage Only
Enrichment is handled by the dedicated enrichment layer.

Changes from original:
- Removed: MITRE technique extraction and mapping creation
- Removed: CVE reference extraction and handling
- Removed: Complex enrichment logic in rule processing
- Added: Enrichment orchestrator trigger
- Simplified: Basic rule storage and metadata
- Kept: YARA/Suricata parsing logic
"""
import json
import logging
import re
import boto3
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone

# Import from the saint-datamodel layer
from saint_datamodel import db_session, RuleRepository
from saint_datamodel.models import RuleSource, DetectionRule
from saint_datamodel.utils import generate_rule_hash, normalize_metadata

# --- Logging and Clients ---
logger = logging.getLogger()
logger.setLevel(logging.INFO)
s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')

# Rule parsing regexes (kept from original)
SNORT_RULE_REGEX = re.compile(
    r'^(alert|log|pass|activate|dynamic|drop|reject|sdrop)\s+'  # action
    r'(\w+)\s+'  # protocol
    r'([^\s]+)\s+([^\s]+)\s+'  # src_ip src_port
    r'([<>-]+)\s+'  # direction
    r'([^\s]+)\s+([^\s]+)\s+'  # dest_ip dest_port
    r'\((.*)\)$',  # options
    re.MULTILINE
)

YARA_RULE_REGEX = re.compile(
    r'^rule\s+(\w+)\s*\{(.*?)\}$',
    re.MULTILINE | re.DOTALL
)

class CrowdStrikeProcessor:
    SOURCE_NAME = "CrowdStrike"

    def __init__(self):
        self.processed_count = 0
        self.created_count = 0
        self.updated_count = 0
        self.skipped_count = 0  # Track skipped duplicate rules
        self.error_count = 0
        self.processed_rule_ids = []

    def get_or_create_source(self, session) -> RuleSource:
        """Gets or creates the 'CrowdStrike' RuleSource."""
        source = session.query(RuleSource).filter_by(name=self.SOURCE_NAME).first()
        if source:
            return source
        new_source = RuleSource(
            name=self.SOURCE_NAME,
            description="Detection rules from CrowdStrike Falcon Intelligence.",
            source_type="Vendor",
            base_url="https://falcon.crowdstrike.com"
        )
        session.add(new_source)
        session.flush()
        return new_source

    def _determine_rule_type_from_filename(self, key: str) -> str:
        """Determine rule type from S3 key filename."""
        key_lower = key.lower()
        if 'yara' in key_lower or key_lower.endswith('.yar') or key_lower.endswith('.yara'):
            return 'yara'
        elif 'suricata' in key_lower or 'snort' in key_lower or key_lower.endswith('.rules'):
            return 'suricata'
        else:
            return 'unknown'

    def parse_rules(self, file_content: str, rule_type: str) -> List[Dict[str, Any]]:
        """Parse rules from file content based on rule type."""
        if rule_type == 'yara':
            return self._parse_yara_rules(file_content)
        elif rule_type == 'suricata':
            return self._parse_suricata_rules(file_content)
        else:
            return self._parse_generic_rules(file_content)

    def _parse_yara_rules(self, file_content: str) -> List[Dict[str, Any]]:
        """Parse YARA rules from file content (SIMPLIFIED - no enrichment)."""
        rules = []
        lines = file_content.split('\n')
        current_rule = []
        in_rule = False
        brace_count = 0
        
        for line in lines:
            stripped_line = line.strip()
            
            # Skip comments and empty lines outside of rules
            if not in_rule and (not stripped_line or stripped_line.startswith('//')):
                continue
            
            # Start of a new rule
            if stripped_line.startswith('rule '):
                if current_rule:  # Finish previous rule if any
                    rule_text = '\n'.join(current_rule)
                    rule_data = self._parse_single_yara_rule(rule_text)
                    if rule_data:
                        rules.append(rule_data)
                
                current_rule = [line]
                in_rule = True
                brace_count = 0
            elif in_rule:
                current_rule.append(line)
                
                # Count braces to know when rule ends
                brace_count += line.count('{') - line.count('}')
                
                if brace_count == 0 and '{' in ''.join(current_rule):
                    # Rule is complete
                    rule_text = '\n'.join(current_rule)
                    rule_data = self._parse_single_yara_rule(rule_text)
                    if rule_data:
                        rules.append(rule_data)
                    
                    current_rule = []
                    in_rule = False
        
        # Handle final rule
        if current_rule:
            rule_text = '\n'.join(current_rule)
            rule_data = self._parse_single_yara_rule(rule_text)
            if rule_data:
                rules.append(rule_data)
        
        return rules

    def _parse_single_yara_rule(self, rule_text: str) -> Optional[Dict[str, Any]]:
        """Parse a single YARA rule (SIMPLIFIED - no enrichment extraction)."""
        match = YARA_RULE_REGEX.match(rule_text.strip())
        if not match:
            return None
        
        rule_name = match.group(1)
        rule_body = match.group(2)
        
        # Extract basic metadata only
        rule_data = {
            'rule_id': f"cs_yara_{rule_name}",
            'name': f"CrowdStrike YARA: {rule_name}",
            'description': f"CrowdStrike YARA rule: {rule_name}",
            'raw_rule': rule_text,
            'rule_format': 'yara',
            'content_length': len(rule_text)
        }
        
        return rule_data

    def _parse_suricata_rules(self, file_content: str) -> List[Dict[str, Any]]:
        """Parse Suricata/Snort rules from file content (SIMPLIFIED)."""
        rules = []
        lines = file_content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            rule_data = self._parse_single_suricata_rule(line, line_num)
            if rule_data:
                rules.append(rule_data)
        
        return rules

    def _parse_single_suricata_rule(self, rule_line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse a single Suricata rule (SIMPLIFIED - no enrichment extraction)."""
        match = SNORT_RULE_REGEX.match(rule_line)
        if not match:
            return None
        
        action = match.group(1)
        protocol = match.group(2)
        options = match.group(7)
        
        # Extract basic info from options
        msg_match = re.search(r'msg:"([^"]+)"', options)
        rule_name = msg_match.group(1) if msg_match else f"CrowdStrike Rule Line {line_num}"
        
        # Generate rule ID from content hash
        rule_hash = generate_rule_hash(rule_line)
        rule_id = f"cs_suricata_{rule_hash[:12]}"
        
        rule_data = {
            'rule_id': rule_id,
            'name': rule_name,
            'description': f"CrowdStrike Suricata rule: {action} {protocol}",
            'raw_rule': rule_line,
            'rule_format': 'suricata',
            'action': action,
            'protocol': protocol,
            'content_length': len(rule_line)
        }
        
        return rule_data

    def _parse_generic_rules(self, file_content: str) -> List[Dict[str, Any]]:
        """Parse generic rule format (SIMPLIFIED)."""
        rules = []
        lines = file_content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # Generate rule ID from line content
            rule_hash = generate_rule_hash(line)
            rule_id = f"cs_generic_{rule_hash[:12]}"
            
            rule_data = {
                'rule_id': rule_id,
                'name': f"CrowdStrike Rule Line {line_num}",
                'description': f"CrowdStrike generic rule from line {line_num}",
                'raw_rule': line,
                'rule_format': 'generic',
                'content_length': len(line)
            }
            
            rules.append(rule_data)
        
        return rules

    def _map_and_upsert_rule(self, rule_data: Dict[str, Any], rule_repo: RuleRepository, source_id: int) -> Optional[DetectionRule]:
        """Map rule data to DetectionRule model and upsert (FIXED - handles existing rules properly)."""
        rule_id = rule_data.get('rule_id')
        if not rule_id:
            logger.warning("Skipping rule with no rule_id")
            return None

        # Store the raw rule content
        rule_content = rule_data.get('raw_rule', '')
        rule_hash = generate_rule_hash(rule_content)

        # FIRST: Check if rule with same hash already exists (regardless of rule_id)
        with rule_repo.session:
            existing_by_hash = rule_repo.session.query(DetectionRule).filter(
                DetectionRule.hash == rule_hash,
                DetectionRule.source_id == source_id
            ).first()
            
            if existing_by_hash:
                # Rule with same content already exists
                self.skipped_count += 1
                logger.info(f"Skipping duplicate rule (hash exists): {rule_id} -> DB ID {existing_by_hash.id}")
                return existing_by_hash

        # Build simplified metadata (NO enrichment data)
        rule_metadata = {
            'rule_format': rule_data.get('rule_format', 'unknown'),
            'content_length': rule_data.get('content_length', 0),
            'source_type': 'crowdstrike',
            'needs_enrichment': True,  # Flag for enrichment layer
            'processor_version': '2.0_simplified',  # Track processor version
            'action': rule_data.get('action'),  # For Suricata rules
            'protocol': rule_data.get('protocol')  # For Suricata rules
        }

        # Build basic tags (NO enrichment - enrichment layer will enhance these)
        basic_tags = [
            "source:crowdstrike",
            f"format:{rule_data.get('rule_format', 'unknown')}"
        ]
        
        # Add format-specific tags
        if rule_data.get('action'):
            basic_tags.append(f"action:{rule_data['action']}")
        if rule_data.get('protocol'):
            basic_tags.append(f"protocol:{rule_data['protocol']}")

        rule_payload = {
            'name': rule_data.get('name', 'CrowdStrike Rule'),
            'description': rule_data.get('description', ''),
            'rule_content': rule_content,
            'rule_type': rule_data.get('rule_format', 'unknown'),
            'severity': 'medium',  # Default severity
            'is_active': True,
            'tags': basic_tags,  # Simple tags, enrichment layer will enhance these
            'rule_metadata': normalize_metadata(rule_metadata)
        }

        # SECOND: Try to find by rule_id and source (normal case)
        db_rule = rule_repo.get_by_source_and_rule_id(source_id=source_id, rule_id=str(rule_id))
        
        if db_rule:
            # Rule exists with same rule_id
            if db_rule.hash != rule_hash:
                # Content changed, update it
                rule_repo.update(db_rule.id, hash=rule_hash, **rule_payload)
                self.updated_count += 1
                logger.info(f"Updated CrowdStrike rule: {rule_id}")
            else:
                # Same content, skip
                self.skipped_count += 1
                logger.info(f"Skipping unchanged rule: {rule_id}")
            return db_rule
        else:
            # THIRD: Create new rule (safe now that we've checked for hash duplicates)
            try:
                db_rule = rule_repo.create(rule_id=str(rule_id), source_id=source_id, hash=rule_hash, **rule_payload)
                self.created_count += 1
                logger.info(f"Created CrowdStrike rule: {rule_id}")
                return db_rule
            except Exception as e:
                if "duplicate key value violates unique constraint" in str(e):
                    self.skipped_count += 1
                    logger.warning(f"Hash collision detected for rule {rule_id}, skipping")
                    return None
                else:
                    raise e

    def process_s3_object(self, bucket: str, key: str):
        """Main processing logic for the S3 file (SIMPLIFIED)."""
        logger.info(f"Processing S3 object: s3://{bucket}/{key}")
        
        try:
            s3_object = s3_client.get_object(Bucket=bucket, Key=key)
            file_content = s3_object['Body'].read().decode('utf-8')
            
            # Determine rule type from filename
            rule_type = self._determine_rule_type_from_filename(key)
            logger.info(f"Processing as {rule_type} format")
            
            # Parse rules
            rules = self.parse_rules(file_content, rule_type)
            logger.info(f"Parsed {len(rules)} rules from {key}")
            
            with db_session() as session:
                rule_repo = RuleRepository(session)
                cs_source = self.get_or_create_source(session)
                
                for rule_data in rules:
                    self.processed_count += 1
                    try:
                        db_rule = self._map_and_upsert_rule(rule_data, rule_repo, cs_source.id)
                        if db_rule:
                            self.processed_rule_ids.append(db_rule.id)

                        # Commit each rule individually to prevent large transaction issues
                        session.commit()

                    except Exception as e:
                        session.rollback()
                        self.error_count += 1
                        logger.error(f"Failed to process rule {rule_data.get('rule_id')}: {e}", exc_info=True)

            # Trigger enrichment after successful processing
            if self.processed_rule_ids:
                self._trigger_enrichment(cs_source.id, self.processed_rule_ids)

        except Exception as e:
            self.error_count += 1
            logger.error(f"Fatal error processing S3 object s3://{bucket}/{key}: {e}", exc_info=True)

        # Log final summary
        logger.info(
            f"CrowdStrike processing finished. "
            f"Rules processed: {self.processed_count}, Created: {self.created_count}, "
            f"Updated: {self.updated_count}, Skipped: {self.skipped_count}, Errors: {self.error_count}"
        )

    def _trigger_enrichment(self, source_id: int, rule_ids: List[int]):
        """Trigger enrichment orchestrator for processed rules."""
        try:
            payload = {
                'source_completed': True,
                'source_id': source_id,
                'rule_ids': rule_ids,
                'source_name': self.SOURCE_NAME,
                'processor_version': '2.0_simplified'
            }
            
            response = lambda_client.invoke(
                FunctionName='saint-enrichment-orchestrator',
                InvocationType='Event',  # Async invocation
                Payload=json.dumps(payload)
            )
            
            logger.info(f"Successfully triggered enrichment for {len(rule_ids)} CrowdStrike rules")
            
        except Exception as e:
            logger.error(f"Failed to trigger enrichment orchestrator: {e}")
            # Don't fail the entire processing if enrichment trigger fails

def lambda_handler(event, context):
    """Main handler triggered by S3 event."""
    processor = CrowdStrikeProcessor()
    
    try:
        for record in event.get('Records', []):
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']

            if key.startswith('crowdstrike/'):
                processor.process_s3_object(bucket=bucket, key=key)
            else:
                logger.warning(f"Skipping file not in 'crowdstrike/' folder: {key}")

        return {
            'statusCode': 200, 
            'body': json.dumps({
                'message': 'CrowdStrike processing complete',
                'processed_count': processor.processed_count,
                'created_count': processor.created_count,
                'updated_count': processor.updated_count,
                'skipped_count': processor.skipped_count,
                'error_count': processor.error_count,
                'enrichment_triggered': len(processor.processed_rule_ids) > 0
            })
        }
        
    except Exception as e:
        logger.error(f"CrowdStrike processor failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'message': 'CrowdStrike processing failed'
            })
        }