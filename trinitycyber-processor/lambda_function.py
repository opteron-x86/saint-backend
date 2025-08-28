# trinity_cyber_processor_enhanced.py
"""
Trinity Cyber Detection Rule Processor 
"""

import json
import logging
import re
import boto3
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set

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
    
    # Trinity Cyber specific mappings
    TAG_CATEGORY_MAPPINGS = {
        "File Type": "data_source",
        "Malware Name": "malware_family", 
        "Malware Classification": "malware_type",
        "Unified Kill Chain": "kill_chain",
        "ATT&CK Tactic": "tactic",
        "ATT&CK Technique": "technique",
        "ATT&CK Sub-technique": "subtechnique",
        "APT Group": "intrusion_set",
        "Threat Actor": "intrusion_set"
    }
    
    # Data source mappings from Trinity Cyber file types
    FILE_TYPE_TO_DATA_SOURCE = {
        "OLE": "Microsoft Office Documents",
        "PDF": "PDF Documents",
        "PE": "Windows Executables", 
        "ELF": "Linux Executables",
        "JAR": "Java Archives",
        "ZIP": "Compressed Archives",
        "JavaScript": "Web Traffic",
        "HTML": "Web Traffic",
        "Email": "Email Gateway",
        "Network": "Network Traffic"
    }

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
            description="Detection rules from Trinity Cyber Inline Active Prevention.", 
            source_type="Vendor", 
            base_url="https://portal.trinitycyber.com"
        )
        session.add(new_source)
        session.flush()
        return new_source

    def _extract_info_controls(self, rule_data: Dict[str, Any]) -> Optional[str]:
        """Extract information control markings from rule data"""
        # Check tags for classification markings
        tags = rule_data.get('tags', [])
        descriptions = rule_data.get('descriptions', [])
        
        # Common patterns for info controls
        patterns = [
            r'CUI[/\\]{0,2}[A-Z,\s]*',
            r'TLP:[A-Z]+',
            r'UNCLASSIFIED[/\\]{0,2}[A-Z,\s]+',
            r'U[/\\]{1,2}FOUO',
            r'PROPIN',
            r'ISVI'
        ]
        
        # Check in tags
        for tag in tags:
            value = tag.get('value', '')
            for pattern in patterns:
                match = re.search(pattern, value, re.IGNORECASE)
                if match:
                    return match.group(0).upper()
        
        # Check in descriptions
        for desc in descriptions:
            desc_text = desc.get('description', '')
            for pattern in patterns:
                match = re.search(pattern, desc_text, re.IGNORECASE)
                if match:
                    return match.group(0).upper()
        
        return None
    
    def _extract_aor(self, rule_data: Dict[str, Any]) -> str:
        """Extract Area of Responsibility - Trinity Cyber is primarily IAP"""
        # Trinity Cyber operates as Inline Active Prevention (IAP)
        # Check tags for specific deployment indicators
        tags = rule_data.get('tags', [])
        
        for tag in tags:
            value = tag.get('value', '').lower()
            if 'cloud' in value:
                if 'aws' in value:
                    return "AWS Cloud"
                elif 'azure' in value:
                    return "Azure Cloud"
                elif 'gcp' in value or 'google' in value:
                    return "Google Cloud"
            elif 'enclave' in value:
                return "Enclave"
            elif 'perimeter' in value or 'edge' in value:
                return "Network Perimeter"
        
        # Default for Trinity Cyber
        return "IAP"
    
    def _extract_data_sources(self, rule_data: Dict[str, Any]) -> List[str]:
        """Extract data sources from Trinity Cyber tags"""
        data_sources = set()
        tags = rule_data.get('tags', [])
        
        for tag in tags:
            category = tag.get('category', '')
            value = tag.get('value', '')
            
            # Map file types to data sources
            if category == "File Type":
                mapped_source = self.FILE_TYPE_TO_DATA_SOURCE.get(value, value)
                data_sources.add(mapped_source)
            
            # Check for explicit data source mentions
            elif category == "Data Source":
                data_sources.add(value)
            
            # Network-based detections
            elif category == "Protocol":
                data_sources.add(f"{value} Traffic")
        
        # Trinity Cyber analyzes inline network traffic by default
        if not data_sources:
            data_sources.add("Network Traffic")
            data_sources.add("IAP Telemetry")
        
        return list(data_sources)
    
    def _extract_malware_info(self, rule_data: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
        """Extract malware family and intrusion set from tags"""
        malware_family = None
        intrusion_set = None
        
        tags = rule_data.get('tags', [])
        
        for tag in tags:
            category = tag.get('category', '')
            value = tag.get('value', '')
            
            if category == "Malware Name":
                malware_family = value
            elif category in ["APT Group", "Threat Actor", "Intrusion Set"]:
                intrusion_set = value
            elif category == "Campaign" and not intrusion_set:
                intrusion_set = value
        
        return malware_family, intrusion_set
    
    def _extract_cwe_from_description(self, rule_data: Dict[str, Any]) -> List[str]:
        """Extract CWE IDs from descriptions or tags"""
        cwe_ids = set()
        
        # Pattern for CWE references
        cwe_pattern = r'CWE[-\s]?(\d+)'
        
        # Check descriptions
        for desc in rule_data.get('descriptions', []):
            desc_text = desc.get('description', '')
            matches = re.findall(cwe_pattern, desc_text, re.IGNORECASE)
            cwe_ids.update([f"CWE-{match}" for match in matches])
        
        # Check tags
        for tag in rule_data.get('tags', []):
            value = tag.get('value', '')
            matches = re.findall(cwe_pattern, value, re.IGNORECASE)
            cwe_ids.update([f"CWE-{match}" for match in matches])
        
        return list(cwe_ids)
    
    def _extract_hunt_id(self, rule_data: Dict[str, Any]) -> Optional[str]:
        """Extract hunt ID from rule data"""
        # Check for hunt identifiers in descriptions or tags
        hunt_patterns = [
            r'HUNT[-\s]?\d{4}[-\s]?\d{3,}',
            r'DCI[-\s]?\d+',
            r'ENT[-\s]?HUNT[-\s]?\d+'
        ]
        
        # Check descriptions
        for desc in rule_data.get('descriptions', []):
            desc_text = desc.get('description', '')
            for pattern in hunt_patterns:
                match = re.search(pattern, desc_text, re.IGNORECASE)
                if match:
                    return match.group(0).upper().replace(' ', '-')
        
        # Check tags
        for tag in rule_data.get('tags', []):
            if tag.get('category', '') == "Hunt ID":
                return tag.get('value', '')
        
        return None

    def _build_rule_metadata(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build comprehensive rule metadata including all required fields"""
        
        # Extract malware and intrusion set info
        malware_family, intrusion_set = self._extract_malware_info(rule_data)
        
        # Build metadata structure
        metadata = {
            # Existing Trinity Cyber fields
            'createTime': rule_data.get('createTime'),
            'updateTime': rule_data.get('updateTime'),
            'rule_platforms': ["IAP"],  # Trinity Cyber platform
            'validation_status': rule_data.get('validation_status', 'unknown'),
            'source_type': 'trinity_cyber',
            'needs_enrichment': True,
            'processor_version': '3.0_enhanced',
            
            # Core metadata fields
            'author': rule_data.get('author') or 'Trinity Cyber',
            'language': 'tcl',  # Trinity Cyber Language
            'references': self._extract_references(rule_data),
            
            # New required metadata fields
            'info_controls': self._extract_info_controls(rule_data),
            'siem_platform': 'Trinity Cyber IAP',
            'aor': self._extract_aor(rule_data),
            'source_org': 'Trinity Cyber',
            'data_sources': self._extract_data_sources(rule_data),
            'modified_by': rule_data.get('modified_by'),
            'hunt_id': self._extract_hunt_id(rule_data),
            'malware_family': malware_family,
            'intrusion_set': intrusion_set,
            'cwe_ids': self._extract_cwe_from_description(rule_data),
            'validation': {
                'testable_via': rule_data.get('testable_via'),
                'asv_action_id': rule_data.get('asv_action_id'),
                'validated': rule_data.get('validated', False),
                'last_tested': rule_data.get('last_tested')
            },
            
            # Trinity Cyber specific fields
            'formula_id': rule_data.get('formulaId'),
            'tag_categories': self._extract_tag_categories(rule_data),
            'kill_chain_phase': self._extract_kill_chain_phase(rule_data),
            'file_types': self._extract_file_types(rule_data),
            'has_implementation': bool(rule_data.get('implementation')),
            'threat_coverage': self._calculate_threat_coverage(rule_data)
        }
        
        return metadata
    
    def _extract_references(self, rule_data: Dict[str, Any]) -> List[str]:
        """Extract references from rule data"""
        references = []
        
        # Check for explicit references field
        if 'references' in rule_data:
            references.extend(rule_data['references'])
        
        # Extract URLs from descriptions
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        for desc in rule_data.get('descriptions', []):
            desc_text = desc.get('description', '')
            urls = re.findall(url_pattern, desc_text)
            references.extend(urls)
        
        return list(set(references))
    
    def _extract_tag_categories(self, rule_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Organize tags by category"""
        tag_dict = {}
        for tag in rule_data.get('tags', []):
            category = tag.get('category', 'uncategorized')
            value = tag.get('value', '')
            if category not in tag_dict:
                tag_dict[category] = []
            tag_dict[category].append(value)
        return tag_dict
    
    def _extract_kill_chain_phase(self, rule_data: Dict[str, Any]) -> Optional[str]:
        """Extract kill chain phase from tags"""
        for tag in rule_data.get('tags', []):
            if tag.get('category') == "Unified Kill Chain":
                return tag.get('value')
        return None
    
    def _extract_file_types(self, rule_data: Dict[str, Any]) -> List[str]:
        """Extract file types from tags"""
        file_types = []
        for tag in rule_data.get('tags', []):
            if tag.get('category') == "File Type":
                file_types.append(tag.get('value'))
        return file_types
    
    def _calculate_threat_coverage(self, rule_data: Dict[str, Any]) -> float:
        """Calculate threat coverage score based on tags"""
        score = 0.0
        tags = rule_data.get('tags', [])
        
        # Points for different tag types
        scoring = {
            "ATT&CK Technique": 10,
            "ATT&CK Sub-technique": 15,
            "Malware Name": 20,
            "APT Group": 25,
            "CVE": 30
        }
        
        for tag in tags:
            category = tag.get('category', '')
            score += scoring.get(category, 5)
        
        # Normalize to 0-100
        return min(100.0, score)
    
    def _build_tags(self, rule_data: Dict[str, Any]) -> List[str]:
        """Build comprehensive tags for the rule"""
        tags = [
            "source:trinity_cyber",
            "platform:iap",
            "format:tcl"
        ]
        
        # Add AOR tag
        aor = self._extract_aor(rule_data)
        if aor:
            tags.append(f"aor:{aor.lower().replace(' ', '_')}")
        
        # Add data source tags
        for ds in self._extract_data_sources(rule_data):
            tags.append(f"data_source:{ds.lower().replace(' ', '_')}")
        
        # Add malware family tag
        malware_family, _ = self._extract_malware_info(rule_data)
        if malware_family:
            tags.append(f"malware:{malware_family.lower()}")
        
        # Add severity if available
        severity = rule_data.get('severity', 'medium')
        tags.append(f"severity:{severity}")
        
        # Process Trinity Cyber tags
        for tag in rule_data.get('tags', []):
            category = tag.get('category', '')
            value = tag.get('value', '')
            
            # Map specific categories to standardized tags
            if category == "ATT&CK Technique":
                # Extract technique ID
                match = re.search(r'T\d{4}(?:\.\d{3})?', value)
                if match:
                    tags.append(f"mitre:{match.group(0)}")
            elif category == "Malware Classification":
                tags.append(f"malware_type:{value.lower()}")
            elif category == "Protocol":
                tags.append(f"protocol:{value.lower()}")
            
            # Keep original tag in namespaced format
            if len(value) < 50:  # Limit tag length
                safe_category = category.lower().replace(' ', '_').replace('-', '_')
                safe_value = value.lower().replace(' ', '_').replace('-', '_')
                tags.append(f"tc_{safe_category}:{safe_value}")
        
        return list(set(tags))  # Remove duplicates

    def _map_and_upsert_rule(self, rule_data: Dict[str, Any], rule_repo: RuleRepository, source_id: int) -> Optional[DetectionRule]:
        """Maps TC data to the DetectionRule model and upserts it with enhanced metadata"""
        rule_id = rule_data.get('formulaId')
        if not rule_id:
            logger.warning("Skipping rule with no 'formulaId'.")
            return None

        # Store the original JSON in the rule_content field
        rule_content = json.dumps(rule_data, sort_keys=True)
        rule_hash = generate_rule_hash(rule_content)

        # Get description from descriptions array
        description = next(iter(rule_data.get('descriptions', [])), {}).get('description', '')

        # Build comprehensive metadata
        rule_metadata = self._build_rule_metadata(rule_data)
        
        # Build comprehensive tags
        tags = self._build_tags(rule_data)

        rule_payload = {
            'name': rule_data.get('title'),
            'description': description,
            'rule_content': rule_content,
            'rule_type': 'tcl',
            'severity': rule_data.get('severity', 'medium'),
            'is_active': rule_data.get('enabled', True),
            'tags': tags,
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
        """Main processing logic for the S3 file"""
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

        logger.info(
            f"Trinity Cyber processing finished. "
            f"Rules processed: {self.processed_count}, Created: {self.created_count}, "
            f"Updated: {self.updated_count}, Errors: {self.error_count}"
        )

    def _trigger_enrichment(self, source_id: int, rule_ids: List[int]):
        """Trigger enrichment orchestrator for processed rules"""
        try:
            payload = {
                'source_completed': True,
                'source_id': source_id,
                'rule_ids': rule_ids,
                'source_name': self.SOURCE_NAME,
                'processor_version': '3.0_enhanced',
                'metadata_fields': [
                    'info_controls', 'aor', 'data_sources', 'malware_family',
                    'intrusion_set', 'cwe_ids', 'hunt_id'
                ]
            }
            
            response = lambda_client.invoke(
                FunctionName='saint-enrichment-orchestrator',
                InvocationType='Event',
                Payload=json.dumps(payload)
            )
            
            logger.info(f"Successfully triggered enrichment for {len(rule_ids)} Trinity Cyber rules")
            
        except Exception as e:
            logger.error(f"Failed to trigger enrichment orchestrator: {e}")
            # Don't fail the entire processing if enrichment trigger fails

def lambda_handler(event, context):
    """Main handler triggered by S3 event"""
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