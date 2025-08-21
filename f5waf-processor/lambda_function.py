# f5_waf_processor.py
"""
Processes F5 WAF attack signatures from JSON files in S3.
- Maps F5 attack signatures to the SAINT database schema
- Creates mappings between attack signatures and MITRE ATT&CK techniques
- Extracts CVE data for processing by the CVE updater
"""
import json
import logging
import re
import boto3
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timezone

# Import from the saint-datamodel layer
from saint_datamodel import db_session, RuleRepository, MitreRepository
from saint_datamodel.models import RuleSource, DetectionRule, RuleMitreMapping
from saint_datamodel.utils import generate_rule_hash

# --- Logging and Clients ---
logger = logging.getLogger()
logger.setLevel(logging.INFO)
s3_client = boto3.client('s3')

# Regex patterns for extraction
MITRE_TECHNIQUE_REGEX = re.compile(r'T(\d{4})(?:\.(\d{3}))?', re.IGNORECASE)
CVE_REGEX = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

# Attack type to MITRE technique mapping (common patterns)
ATTACK_TYPE_MITRE_MAPPING = {
    'Server Side Code Injection': ['T1190'],  # Exploit Public-Facing Application
    'SQL Injection': ['T1190'],  # Exploit Public-Facing Application  
    'Cross Site Scripting (XSS)': ['T1190'],  # Exploit Public-Facing Application
    'Command Execution': ['T1059'],  # Command and Scripting Interpreter
    'Directory Traversal': ['T1083'],  # File and Directory Discovery
    'Information Leakage': ['T1083'],  # File and Directory Discovery
    'Detection Evasion': ['T1055'],  # Process Injection
    'Remote File Inclusion': ['T1105'],  # Ingress Tool Transfer
    'Local File Inclusion': ['T1083'],  # File and Directory Discovery
    'XML External Entity (XXE)': ['T1190'],  # Exploit Public-Facing Application
    'Server-Side Request Forgery (SSRF)': ['T1190'],  # Exploit Public-Facing Application
}

def is_valid_mitre_technique_id(technique_id: str) -> bool:
    """Validate if a technique ID is within MITRE ATT&CK Enterprise ranges."""
    match = re.match(r'^T(\d{4})(?:\.(\d{3}))?$', technique_id.upper())
    if not match:
        return False
    
    main_id = int(match.group(1))
    sub_id = match.group(2)
    
    # MITRE ATT&CK Enterprise uses T1xxx range primarily
    if 1000 <= main_id <= 1700:  # Generous range covering current and future techniques
        if sub_id:
            sub_num = int(sub_id)
            return 1 <= sub_num <= 999
        return True
    
    return False

class F5WAFProcessor:
    SOURCE_NAME = "F5 WAF"

    def __init__(self):
        self.processed_count = 0
        self.created_count = 0
        self.updated_count = 0
        self.mitre_mappings_created = 0
        self.cve_references_extracted = 0
        self.error_count = 0

    def get_or_create_source(self, session) -> RuleSource:
        """Gets or creates the 'F5 WAF' RuleSource."""
        source = session.query(RuleSource).filter_by(name=self.SOURCE_NAME).first()
        if source:
            return source
        new_source = RuleSource(
            name=self.SOURCE_NAME,
            description="Attack signatures from F5 Distributed Cloud Web Application Firewall.",
            source_type="Vendor",
            base_url="https://docs.cloud.f5.com"
        )
        session.add(new_source)
        session.flush()
        return new_source

    def extract_attack_signatures_from_json(self, json_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract attack signatures from the F5 WAF JSON structure.
        The signatures are nested in pageProps.docData.scope.JsonData
        """
        try:
            # Navigate the nested JSON structure
            page_props = json_data.get('pageProps', {})
            doc_data = page_props.get('docData', {})
            scope = doc_data.get('scope', {})
            signatures = scope.get('JsonData', [])
            
            if not signatures:
                logger.warning("No attack signatures found in JSON data")
                return []
            
            logger.info(f"Extracted {len(signatures)} attack signatures from JSON")
            return signatures
            
        except Exception as e:
            logger.error(f"Failed to extract attack signatures from JSON: {e}")
            return []

    def _extract_mitre_techniques_from_signature(self, signature: Dict[str, Any]) -> Set[str]:
        """Extract MITRE technique IDs from attack signature data."""
        techniques = set()
        
        # 1. Look for explicit MITRE references in description
        description = signature.get('description', '') or ''
        matches = MITRE_TECHNIQUE_REGEX.findall(description)
        for match in matches:
            technique_id = f"T{match[0]}"
            if match[1]:  # Sub-technique
                technique_id += f".{match[1]}"
            if is_valid_mitre_technique_id(technique_id):
                techniques.add(technique_id.upper())
        
        # 2. Map attack type to common MITRE techniques
        attack_type = signature.get('attack_type', '') or ''
        if attack_type in ATTACK_TYPE_MITRE_MAPPING:
            for technique in ATTACK_TYPE_MITRE_MAPPING[attack_type]:
                techniques.add(technique)
        
        # 3. Look for MITRE references in signature references (with null check)
        references = signature.get('references')
        if references:  # Only iterate if references is not None
            for ref in references:
                if isinstance(ref, str):
                    matches = MITRE_TECHNIQUE_REGEX.findall(ref)
                    for match in matches:
                        technique_id = f"T{match[0]}"
                        if match[1]:
                            technique_id += f".{match[1]}"
                        if is_valid_mitre_technique_id(technique_id):
                            techniques.add(technique_id.upper())
        
        return techniques

    def _extract_cve_references(self, signature: Dict[str, Any]) -> Set[str]:
        """Extract CVE IDs from F5 attack signature data."""
        cves = set()
        
        # Extract from references array (with null check)
        references = signature.get('references')
        if references:  # Only iterate if references is not None
            for ref in references:
                if isinstance(ref, str):
                    matches = CVE_REGEX.findall(ref)
                    cves.update(cve.upper() for cve in matches)
        
        # Extract from description
        description = signature.get('description', '') or ''
        matches = CVE_REGEX.findall(description)
        cves.update(cve.upper() for cve in matches)
        
        return cves

    def _map_and_upsert_rule(self, signature: Dict[str, Any], rule_repo: RuleRepository, source_id: int) -> Optional[DetectionRule]:
        """Map F5 attack signature to DetectionRule and upsert to database."""
        try:
            # Parse last_update timestamp
            last_update_str = signature.get('last_update', '')
            try:
                last_update = datetime.strptime(last_update_str, '%Y/%m/%d %H:%M:%S')
                last_update = last_update.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                last_update = datetime.now(timezone.utc)
            
            # Build rule content from signature data
            rule_content = {
                'signature_id': signature.get('id'),
                'attack_type': signature.get('attack_type'),
                'risk': signature.get('risk'),
                'accuracy': signature.get('accuracy'),
                'applies_to': signature.get('applies_to'),
                'systems': signature.get('systems', []),
                'description': signature.get('description'),
                'references': signature.get('references', []) or []  # Handle None case
            }
            
            # Create rule data for database - using only fields that exist on DetectionRule model
            rule_data = {
                'rule_id': str(signature['id']),
                'name': signature.get('name', f"F5 Attack Signature {signature['id']}"),
                'description': signature.get('description', ''),
                'rule_content': json.dumps(rule_content),
                'rule_type': 'attack_signature',
                'severity': self._map_risk_to_severity(signature.get('risk', 'Medium')),
                'source_id': source_id,
                'rule_metadata': {
                    'attack_type': signature.get('attack_type'),
                    'risk': signature.get('risk'),
                    'accuracy': signature.get('accuracy'),
                    'applies_to': signature.get('applies_to'),
                    'systems': signature.get('systems', []),
                    'last_update': last_update_str
                }
            }
            
            # Generate hash for comparison
            rule_hash = generate_rule_hash(rule_data['rule_content'])
            rule_data['hash'] = rule_hash
            
            # Upsert rule
            existing_rule = rule_repo.get_by_source_and_rule_id(source_id, rule_data['rule_id'])
            if existing_rule:
                # Compare hash to see if rule has changed
                if existing_rule.hash != rule_hash:
                    logger.debug(f"Updating rule {rule_data['rule_id']}")
                    for key, value in rule_data.items():
                        setattr(existing_rule, key, value)
                    self.updated_count += 1
                    return existing_rule
                else:
                    logger.debug(f"Rule {rule_data['rule_id']} unchanged")
                    return existing_rule
            else:
                logger.debug(f"Creating new rule {rule_data['rule_id']}")
                new_rule = DetectionRule(**rule_data)
                rule_repo.session.add(new_rule)
                rule_repo.session.flush()
                self.created_count += 1
                return new_rule
                
        except Exception as e:
            logger.error(f"Failed to map attack signature {signature.get('id')}: {e}", exc_info=True)
            return None

    def _map_risk_to_severity(self, risk: str) -> str:
        """Map F5 risk levels to standard severity levels."""
        risk_mapping = {
            'Low': 'low',
            'Medium': 'medium',
            'High': 'high',
            'Critical': 'critical'
        }
        return risk_mapping.get(risk, 'medium')

    def _map_mitre_techniques(self, db_rule: DetectionRule, signature: Dict[str, Any], mitre_repo: MitreRepository):
        """Create MITRE technique mappings for the rule."""
        techniques = self._extract_mitre_techniques_from_signature(signature)
        
        for technique_id in techniques:
            try:
                mitre_technique = mitre_repo.get_technique_by_id(technique_id)
                if not mitre_technique:
                    logger.warning(f"MITRE technique {technique_id} not found in database")
                    continue
                
                # Check if mapping already exists
                existing_mapping = mitre_repo.session.query(RuleMitreMapping).filter_by(
                    rule_id=db_rule.id,
                    technique_id=mitre_technique.id
                ).first()
                
                if not existing_mapping:
                    mapping = RuleMitreMapping(
                        rule_id=db_rule.id,
                        technique_id=mitre_technique.id,
                        mapping_source=self.SOURCE_NAME,
                        mapping_confidence=0.8  # Default confidence for F5 mappings
                    )
                    mitre_repo.session.add(mapping)
                    self.mitre_mappings_created += 1
                    logger.debug(f"Created MITRE mapping: Rule {db_rule.rule_id} -> {technique_id}")
                    
            except Exception as e:
                logger.error(f"Failed to create MITRE mapping for {technique_id}: {e}")

    def process_s3_object(self, bucket: str, key: str):
        """Process a single S3 object containing F5 WAF attack signatures."""
        logger.info(f"Processing S3 object: s3://{bucket}/{key}")
        
        try:
            s3_object = s3_client.get_object(Bucket=bucket, Key=key)
            file_content = s3_object['Body'].read().decode('utf-8')
            
            # Parse JSON data
            try:
                json_data = json.loads(file_content)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON from {key}: {e}")
                self.error_count += 1
                return
            
            # Extract attack signatures from nested JSON structure
            signatures = self.extract_attack_signatures_from_json(json_data)
            if not signatures:
                logger.warning(f"No attack signatures found in {key}")
                return
            
            logger.info(f"Processing {len(signatures)} attack signatures from {key}")
            
            with db_session() as session:
                rule_repo = RuleRepository(session)
                mitre_repo = MitreRepository(session)
                f5_source = self.get_or_create_source(session)
                
                for signature in signatures:
                    self.processed_count += 1
                    try:
                        logger.debug(f"Processing signature: {signature.get('id', 'unknown')}")
                        db_rule = self._map_and_upsert_rule(signature, rule_repo, f5_source.id)
                        if not db_rule:
                            logger.warning(f"Failed to create/update signature: {signature.get('id', 'unknown')}")
                            continue

                        self._map_mitre_techniques(db_rule, signature, mitre_repo)
                        
                        # Count CVE references for metadata
                        cve_refs = self._extract_cve_references(signature)
                        self.cve_references_extracted += len(cve_refs)

                        session.commit()
                        logger.debug(f"Successfully processed signature: {signature.get('id', 'unknown')}")

                    except Exception as e:
                        session.rollback()
                        self.error_count += 1
                        logger.error(f"Failed to process signature {signature.get('id')}: {e}", exc_info=True)

        except Exception as e:
            self.error_count += 1
            logger.error(f"Fatal error processing S3 object s3://{bucket}/{key}: {e}", exc_info=True)

        logger.info(
            f"F5 WAF processing finished. "
            f"Signatures: {self.processed_count}, Created: {self.created_count}, Updated: {self.updated_count}, "
            f"MITRE Mappings: {self.mitre_mappings_created}, CVE References: {self.cve_references_extracted}, "
            f"Errors: {self.error_count}"
        )

def lambda_handler(event, context):
    """Main handler triggered by S3 event."""
    processor = F5WAFProcessor()
    for record in event.get('Records', []):
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']

        if key.startswith('f5waf/'):
            processor.process_s3_object(bucket=bucket, key=key)
        else:
            logger.warning(f"Skipping file not in 'f5waf/' folder: {key}")

    return {'statusCode': 200, 'body': json.dumps({'message': 'F5 WAF processing complete.'})}