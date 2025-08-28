# f5_waf_processor_enhanced.py
"""
Enhanced F5 WAF Detection Rule Processor
"""
import json
import logging
import re
import boto3
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from saint_datamodel import db_session, RuleRepository
from saint_datamodel.models import RuleSource, DetectionRule
from saint_datamodel.utils import generate_rule_hash, normalize_metadata

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')


class F5WafProcessor:
    SOURCE_NAME = "F5 WAF"
    
    # Attack type to MITRE tactic mapping
    ATTACK_TYPE_TO_TACTIC = {
        'Cross Site Scripting (XSS)': 'Initial Access',
        'SQL Injection': 'Initial Access',
        'Command Injection': 'Execution',
        'Remote File Include': 'Execution',
        'Local File Include': 'Collection',
        'Directory Traversal': 'Discovery',
        'Buffer Overflow': 'Privilege Escalation',
        'XML External Entity': 'Collection',
        'Server Side Request Forgery': 'Lateral Movement',
        'Denial of Service': 'Impact',
        'Authentication Bypass': 'Defense Evasion',
        'Session Hijacking': 'Credential Access',
        'Information Disclosure': 'Collection',
        'Code Injection': 'Execution',
        'LDAP Injection': 'Initial Access'
    }
    
    def __init__(self):
        self.processed_count = 0
        self.created_count = 0
        self.updated_count = 0
        self.skipped_count = 0
        self.error_count = 0
        self.processed_rule_ids = []
        
    def get_or_create_source(self, session) -> RuleSource:
        source = session.query(RuleSource).filter_by(name=self.SOURCE_NAME).first()
        if source:
            return source
            
        new_source = RuleSource(
            name=self.SOURCE_NAME,
            description="Web Application Firewall signatures from F5 Networks",
            source_type="WAF",
            base_url="https://support.f5.com"
        )
        session.add(new_source)
        session.flush()
        return new_source
    
    def _extract_metadata(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract comprehensive metadata from F5 rule data"""
        
        attack_type = rule_data.get('attack_type', '')
        systems = rule_data.get('systems', [])
        
        metadata = {
            # Core fields
            'rule_format': 'f5_waf',
            'source_type': 'waf',
            'processor_version': '3.0_enhanced',
            'needs_enrichment': True,
            
            # Required metadata fields
            'siem_platform': 'F5 Advanced WAF',
            'source_org': 'F5 Networks',
            'aor': 'Network Perimeter',  # WAF rules protect perimeter
            'info_controls': 'TLP:WHITE',
            'author': 'F5 Security Research',
            'language': 'waf_signature',
            
            # Data sources
            'data_sources': self._extract_data_sources(rule_data),
            
            # F5-specific fields
            'signature_id': rule_data.get('id'),
            'attack_type': attack_type,
            'risk_level': rule_data.get('risk', 'Medium'),
            'accuracy': rule_data.get('accuracy', 'Medium'),
            'applies_to': rule_data.get('applies_to', 'Request'),
            'target_systems': systems,
            'last_update': rule_data.get('last_update'),
            
            # Enhanced threat intel
            'mitre_tactic': self.ATTACK_TYPE_TO_TACTIC.get(attack_type),
            'references': rule_data.get('references', '').split('\n') if rule_data.get('references') else [],
            
            # Validation info
            'validation': {
                'testable_via': 'F5 WAF',
                'accuracy': rule_data.get('accuracy', 'Medium'),
                'false_positive_rate': 'High' if rule_data.get('accuracy') == 'Low' else 'Medium',
                'validated': True,
                'last_tested': rule_data.get('last_update')
            }
        }
        
        # Extract CVE/CWE from description
        description = rule_data.get('description', '')
        metadata['cve_ids'] = self._extract_cve_refs(description)
        metadata['cwe_ids'] = self._extract_cwe_refs(description)
        
        # Extract malware if mentioned
        metadata['malware_family'] = self._extract_malware(description)
        
        return metadata
    
    def _extract_data_sources(self, rule_data: Dict[str, Any]) -> List[str]:
        """Determine data sources based on rule configuration"""
        data_sources = ['Web Application Traffic', 'HTTP/HTTPS Logs']
        
        applies_to = rule_data.get('applies_to', '')
        if 'Request' in applies_to:
            data_sources.append('HTTP Request Headers')
            data_sources.append('HTTP Request Body')
        if 'Response' in applies_to:
            data_sources.append('HTTP Response Headers')
            data_sources.append('HTTP Response Body')
        if 'Cookie' in applies_to:
            data_sources.append('HTTP Cookies')
            
        # Add based on attack type
        attack_type = rule_data.get('attack_type', '')
        if 'SQL' in attack_type:
            data_sources.append('Database Query Logs')
        if 'File' in attack_type:
            data_sources.append('File Access Logs')
        if 'XML' in attack_type:
            data_sources.append('XML Parser Logs')
            
        return list(set(data_sources))
    
    def _extract_cve_refs(self, text: str) -> List[str]:
        """Extract CVE references from text"""
        pattern = r'CVE-\d{4}-\d{4,}'
        matches = re.findall(pattern, text, re.IGNORECASE)
        return [match.upper() for match in matches]
    
    def _extract_cwe_refs(self, text: str) -> List[str]:
        """Extract CWE references from text"""
        # Map attack types to CWE IDs
        attack_to_cwe = {
            'Cross Site Scripting': ['CWE-79'],
            'SQL Injection': ['CWE-89'],
            'Command Injection': ['CWE-77', 'CWE-78'],
            'Directory Traversal': ['CWE-22'],
            'Buffer Overflow': ['CWE-120'],
            'XML External Entity': ['CWE-611'],
            'LDAP Injection': ['CWE-90']
        }
        
        cwe_ids = []
        for attack_type, cwes in attack_to_cwe.items():
            if attack_type in text:
                cwe_ids.extend(cwes)
                
        # Also search for explicit CWE references
        pattern = r'CWE-\d+'
        matches = re.findall(pattern, text, re.IGNORECASE)
        cwe_ids.extend([match.upper() for match in matches])
        
        return list(set(cwe_ids))
    
    def _extract_malware(self, text: str) -> Optional[str]:
        """Extract malware family if mentioned"""
        malware_patterns = [
            'backdoor', 'trojan', 'ransomware', 'worm', 'rootkit',
            'botnet', 'webshell', 'cryptominer', 'stealer'
        ]
        
        text_lower = text.lower()
        for pattern in malware_patterns:
            if pattern in text_lower:
                return pattern.capitalize()
        return None
    
    def _build_tags(self, rule_data: Dict[str, Any], metadata: Dict[str, Any]) -> List[str]:
        """Build comprehensive tags"""
        tags = ['source:f5_waf']
        
        # Attack type
        attack_type = rule_data.get('attack_type', '')
        if attack_type:
            tags.append(f"attack:{attack_type.lower().replace(' ', '_').replace('(', '').replace(')', '')}")
        
        # Risk level
        risk = rule_data.get('risk', 'medium').lower()
        tags.append(f"severity:{risk}")
        
        # Accuracy
        accuracy = rule_data.get('accuracy', 'medium').lower()
        tags.append(f"accuracy:{accuracy}")
        
        # Target systems
        for system in rule_data.get('systems', []):
            tags.append(f"target:{system.lower().replace(' ', '_')}")
        
        # MITRE tactic if mapped
        if metadata.get('mitre_tactic'):
            tags.append(f"tactic:{metadata['mitre_tactic'].lower().replace(' ', '_')}")
        
        # Apply scope
        applies_to = rule_data.get('applies_to', '').lower()
        if applies_to:
            tags.append(f"scope:{applies_to}")
        
        tags.append('aor:network_perimeter')
        tags.append('type:waf_signature')
        
        return tags
    
    def _determine_severity(self, rule_data: Dict[str, Any]) -> str:
        """Map F5 risk level to standard severity"""
        risk = rule_data.get('risk', 'Medium').lower()
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'informational': 'low'
        }
        return severity_map.get(risk, 'medium')
    
    def process_rules(self, rules_data: List[Dict[str, Any]], source_id: int):
        """Process F5 rules into database"""
        with db_session() as session:
            rule_repo = RuleRepository(session)
            
            for rule_data in rules_data:
                self.processed_count += 1
                
                try:
                    # Generate rule ID
                    rule_id = f"f5_sig_{rule_data.get('id')}"
                    rule_content = json.dumps(rule_data, sort_keys=True)
                    rule_hash = generate_rule_hash(rule_content)
                    
                    # Extract metadata and tags
                    metadata = self._extract_metadata(rule_data)
                    tags = self._build_tags(rule_data, metadata)
                    
                    # Parse description for summary
                    description = rule_data.get('description', '')
                    summary_match = re.search(r'Summary:\s*(.+?)(?:Impact:|$)', description, re.DOTALL)
                    summary = summary_match.group(1).strip() if summary_match else rule_data.get('name', '')
                    
                    rule_payload = {
                        'name': rule_data.get('name', ''),
                        'description': summary[:500],
                        'rule_content': rule_content,
                        'rule_type': 'waf_signature',
                        'severity': self._determine_severity(rule_data),
                        'is_active': True,
                        'tags': tags,
                        'rule_metadata': normalize_metadata(metadata)
                    }
                    
                    # Check if rule exists
                    existing_rule = rule_repo.get_by_source_and_rule_id(source_id, rule_id)
                    
                    if existing_rule:
                        # Check if update needed
                        needs_update = (
                            existing_rule.hash != rule_hash or
                            existing_rule.rule_metadata.get('processor_version') != metadata['processor_version']
                        )
                        
                        if needs_update:
                            rule_repo.update(existing_rule.id, hash=rule_hash, **rule_payload)
                            self.updated_count += 1
                            logger.info(f"Updated rule: {rule_id}")
                        else:
                            self.skipped_count += 1
                    else:
                        # Create new rule
                        db_rule = rule_repo.create(
                            rule_id=rule_id,
                            source_id=source_id,
                            hash=rule_hash,
                            **rule_payload
                        )
                        self.created_count += 1
                        self.processed_rule_ids.append(db_rule.id)
                        logger.info(f"Created rule: {rule_id}")
                    
                    session.commit()
                    
                except Exception as e:
                    session.rollback()
                    self.error_count += 1
                    logger.error(f"Failed to process F5 rule {rule_data.get('id')}: {e}")
    
    def process_s3_object(self, bucket: str, key: str):
        """Process S3 object containing F5 rules"""
        logger.info(f"Processing S3 object: s3://{bucket}/{key}")
        
        try:
            # Download and parse JSON
            s3_object = s3_client.get_object(Bucket=bucket, Key=key)
            content = s3_object['Body'].read()
            
            # Parse JSON structure
            data = json.loads(content)
            
            # Extract rules array from nested structure
            if 'pageProps' in data and 'docData' in data['pageProps']:
                rules_data = data['pageProps']['docData']['scope']['JsonData']
            elif 'JsonData' in data:
                rules_data = data['JsonData']
            elif isinstance(data, list):
                rules_data = data
            else:
                logger.error(f"Unknown F5 data structure in {key}")
                return
            
            logger.info(f"Found {len(rules_data)} F5 rules to process")
            
            # Get source ID
            with db_session() as session:
                source = self.get_or_create_source(session)
                source_id = source.id
                session.commit()
            
            # Process rules
            self.process_rules(rules_data, source_id)
            
            # Trigger enrichment
            if self.processed_rule_ids:
                self._trigger_enrichment(source_id, self.processed_rule_ids)
                
        except Exception as e:
            logger.error(f"Fatal error processing {key}: {e}", exc_info=True)
            self.error_count += 1
        
        logger.info(
            f"F5 processing complete - Created: {self.created_count}, "
            f"Updated: {self.updated_count}, Skipped: {self.skipped_count}, "
            f"Errors: {self.error_count}"
        )
    
    def _trigger_enrichment(self, source_id: int, rule_ids: List[int]):
        """Trigger enrichment orchestrator"""
        try:
            payload = {
                'source_completed': True,
                'source_id': source_id,
                'rule_ids': rule_ids,
                'source_name': self.SOURCE_NAME,
                'processor_version': '3.0_enhanced'
            }
            
            lambda_client.invoke(
                FunctionName='saint-enrichment-orchestrator',
                InvocationType='Event',
                Payload=json.dumps(payload)
            )
            
            logger.info(f"Triggered enrichment for {len(rule_ids)} F5 rules")
            
        except Exception as e:
            logger.error(f"Failed to trigger enrichment: {e}")


def lambda_handler(event, context):
    """Lambda handler for S3 events"""
    processor = F5WafProcessor()
    
    try:
        for record in event.get('Records', []):
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']
            
            if key.startswith('f5waf/') or key.startswith('f5-waf/'):
                processor.process_s3_object(bucket, key)
            else:
                logger.warning(f"Skipping file not in f5waf/ folder: {key}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'F5 processing complete',
                'processed': processor.processed_count,
                'created': processor.created_count,
                'updated': processor.updated_count,
                'skipped': processor.skipped_count,
                'errors': processor.error_count
            })
        }
        
    except Exception as e:
        logger.error(f"Lambda handler error: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }