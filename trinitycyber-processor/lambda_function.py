# trinity_cyber_processor_simplified.py
"""
Simplified Trinity Cyber Processor - Parsing and Storage Only
Enrichment is handled by the dedicated enrichment layer.

Changes from original:
- Removed: MITRE technique extraction
- Removed: CVE reference extraction  
- Removed: Enriched tag building
- Removed: MITRE mapping creation
- Added: Enrichment orchestrator trigger
- Simplified: Basic rule storage and metadata
"""
import json
import logging
import boto3
from typing import Dict, List, Any, Optional

# Import from the saint-datamodel layer
from saint_datamodel import db_session, RuleRepository
from saint_datamodel.models import RuleSource, DetectionRule
from saint_datamodel.utils import generate_rule_hash, normalize_metadata

# --- Logging and Clients ---
logger = logging.getLogger()
logger.setLevel(logging.INFO)
s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')

class TrinityCyberProcessor:
    SOURCE_NAME = "Trinity Cyber"

    def __init__(self):
        self.processed_count = 0
        self.created_count = 0
        self.updated_count = 0
        self.error_count = 0
        self.processed_rule_ids = []

    def get_or_create_source(self, session) -> RuleSource:
        """Gets or creates the 'Trinity Cyber' RuleSource."""
        source = session.query(RuleSource).filter_by(name=self.SOURCE_NAME).first()
        if source:
            return source
        new_source = RuleSource(
            name=self.SOURCE_NAME, 
            description="Detection rules from Trinity Cyber.", 
            source_type="Vendor", 
            base_url="https://portal.trinitycyber.com"
        )
        session.add(new_source)
        session.flush()
        return new_source

    def _map_and_upsert_rule(self, rule_data: Dict[str, Any], rule_repo: RuleRepository, source_id: int) -> Optional[DetectionRule]:
        """Maps TC data to the DetectionRule model and upserts it (SIMPLIFIED)."""
        rule_id = rule_data.get('formulaId')
        if not rule_id:
            logger.warning("Skipping rule with no 'formulaId'.")
            return None

        # Store the original, unmodified JSON in the rule_content field
        rule_content = json.dumps(rule_data)
        rule_hash = generate_rule_hash(rule_content)

        # Get description from descriptions array
        description = next(iter(rule_data.get('descriptions', [])), {}).get('description', '')

        # Build simplified metadata (NO enrichment data - that's handled by enrichment layer)
        rule_metadata = {
            'createTime': rule_data.get('createTime'),
            'updateTime': rule_data.get('updateTime'),
            'rule_platforms': ["IAP"],  # Trinity Cyber Inline Active Prevention platform
            'validation_status': rule_data.get('validation_status', 'unknown'),
            'source_type': 'trinity_cyber',
            'needs_enrichment': True,  # Flag for enrichment layer
            'processor_version': '2.0_simplified'  # Track processor version
        }

        # Build basic tags (NO enrichment - enrichment layer will add MITRE/CVE tags)
        basic_tags = []
        for tag in rule_data.get('tags', []):
            category = tag.get('category', 'tag')
            value = tag.get('value', '')
            if category and value:
                # Store original tag format for enrichment layer to process
                basic_tags.append(f"{category}:{value}")

        # Add source-specific basic tags
        basic_tags.extend([
            "source:trinity_cyber",
            "platform:iap",
            "format:tcl"
        ])

        rule_payload = {
            'name': rule_data.get('title'),
            'description': description,
            'rule_content': rule_content,
            'rule_type': 'tcl',
            'severity': rule_data.get('severity', 'medium'),
            'is_active': rule_data.get('enabled', True),
            'tags': basic_tags,  # Simple tags, enrichment layer will enhance these
            'rule_metadata': normalize_metadata(rule_metadata)
        }

        # Upsert rule
        db_rule = rule_repo.get_by_source_and_rule_id(source_id=source_id, rule_id=str(rule_id))
        if db_rule:
            if db_rule.hash != rule_hash:
                rule_repo.update(db_rule.id, hash=rule_hash, **rule_payload)
                self.updated_count += 1
                logger.info(f"Updated Trinity Cyber rule: {rule_id}")
        else:
            db_rule = rule_repo.create(rule_id=str(rule_id), source_id=source_id, hash=rule_hash, **rule_payload)
            self.created_count += 1
            logger.info(f"Created Trinity Cyber rule: {rule_id}")

        return db_rule

    def process_s3_object(self, bucket: str, key: str):
        """Main processing logic for the S3 file (SIMPLIFIED)."""
        logger.info(f"Processing S3 object: s3://{bucket}/{key}")
        
        try:
            s3_object = s3_client.get_object(Bucket=bucket, Key=key)
            ruleset = json.loads(s3_object['Body'].read().decode('utf-8'))

            with db_session() as session:
                rule_repo = RuleRepository(session)
                tc_source = self.get_or_create_source(session)

                for rule_data in ruleset:
                    self.processed_count += 1
                    try:
                        db_rule = self._map_and_upsert_rule(rule_data, rule_repo, tc_source.id)
                        if db_rule:
                            self.processed_rule_ids.append(db_rule.id)

                        # Commit each rule individually to prevent large transaction issues
                        session.commit()

                    except Exception as e:
                        session.rollback()
                        self.error_count += 1
                        logger.error(f"Failed to process rule {rule_data.get('formulaId')}: {e}", exc_info=True)

            # Trigger enrichment after successful processing
            if self.processed_rule_ids:
                self._trigger_enrichment(tc_source.id, self.processed_rule_ids)

        except Exception as e:
            self.error_count += 1
            logger.error(f"Fatal error processing S3 object s3://{bucket}/{key}: {e}", exc_info=True)

        # Log final summary
        logger.info(
            f"Trinity Cyber processing finished. "
            f"Rules processed: {self.processed_count}, Created: {self.created_count}, "
            f"Updated: {self.updated_count}, Errors: {self.error_count}"
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
            
            logger.info(f"Successfully triggered enrichment for {len(rule_ids)} Trinity Cyber rules")
            
        except Exception as e:
            logger.error(f"Failed to trigger enrichment orchestrator: {e}")
            # Don't fail the entire processing if enrichment trigger fails
            # The enrichment can be run manually or on schedule if needed

def lambda_handler(event, context):
    """Main handler triggered by S3 event."""
    processor = TrinityCyberProcessor()
    
    try:
        for record in event.get('Records', []):
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']

            if key.startswith('trinitycyber/'):
                processor.process_s3_object(bucket=bucket, key=key)
            else:
                logger.warning(f"Skipping file not in 'trinitycyber/' folder: {key}")

        return {
            'statusCode': 200, 
            'body': json.dumps({
                'message': 'Trinity Cyber processing complete',
                'processed_count': processor.processed_count,
                'created_count': processor.created_count,
                'updated_count': processor.updated_count,
                'error_count': processor.error_count,
                'enrichment_triggered': len(processor.processed_rule_ids) > 0
            })
        }
        
    except Exception as e:
        logger.error(f"Trinity Cyber processor failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'message': 'Trinity Cyber processing failed'
            })
        }