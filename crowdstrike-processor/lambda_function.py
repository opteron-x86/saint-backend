# crowdstrike_processor_rewritten.py
"""
CrowdStrike Detection Rule Processor
"""
import json
import logging
import re
import boto3
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone

from saint_datamodel import db_session, RuleRepository
from saint_datamodel.models import RuleSource, DetectionRule
from saint_datamodel.utils import generate_rule_hash, normalize_metadata

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')


class CrowdStrikeProcessor:
    SOURCE_NAME = "CrowdStrike"
    
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
            description="Detection rules from CrowdStrike Falcon Intelligence.",
            source_type="Vendor",
            base_url="https://falcon.crowdstrike.com"
        )
        session.add(new_source)
        session.flush()
        return new_source

    def parse_yara_file(self, content: str) -> List[Dict[str, Any]]:
        """Parse CrowdStrike YARA ruleset"""
        rules = []
        
        # Remove import statements and comments from the top
        lines = content.split('\n')
        content_without_headers = []
        in_rule = False
        
        for line in lines:
            if line.strip().startswith('rule '):
                in_rule = True
            if in_rule:
                content_without_headers.append(line)
        
        content_clean = '\n'.join(content_without_headers)
        
        # Split into individual rules using regex
        rule_pattern = re.compile(
            r'rule\s+(\w+)(?:\s*:\s*([^\s{]+))?\s*\{(.*?)\n\}',
            re.DOTALL | re.MULTILINE
        )
        
        for match in rule_pattern.finditer(content_clean):
            rule_name = match.group(1)
            tags = match.group(2).split() if match.group(2) else []
            rule_body = match.group(3)
            
            # Extract metadata
            metadata = self._parse_yara_metadata(rule_body)
            
            # Get full rule text including the rule declaration
            rule_text = match.group(0)
            
            rule_data = {
                'rule_id': f"cs_yara_{rule_name}",
                'name': rule_name,
                'description': metadata.get('description', f"CrowdStrike YARA rule: {rule_name}"),
                'author': metadata.get('copyright', 'CrowdStrike Inc.'),
                'raw_rule': rule_text,
                'rule_format': 'yara',
                'tags': tags,
                'metadata': metadata
            }
            rules.append(rule_data)
        
        logger.info(f"Parsed {len(rules)} YARA rules")
        return rules

    def _parse_yara_metadata(self, rule_body: str) -> Dict[str, Any]:
        """Extract metadata from YARA rule body"""
        metadata = {}
        
        meta_match = re.search(r'meta:\s*(.*?)(?:strings:|condition:)', rule_body, re.DOTALL)
        if meta_match:
            meta_section = meta_match.group(1)
            
            # Parse each metadata field
            meta_fields = re.findall(r'(\w+)\s*=\s*"([^"]*)"', meta_section)
            for key, value in meta_fields:
                metadata[key] = value
            
            # Parse metadata without quotes (numbers, booleans)
            meta_fields_unquoted = re.findall(r'(\w+)\s*=\s*([^\s\n]+)', meta_section)
            for key, value in meta_fields_unquoted:
                if key not in metadata and value != '"':
                    metadata[key] = value
        
        return metadata

    def parse_suricata_file(self, content: str) -> List[Dict[str, Any]]:
        """Parse CrowdStrike Suricata/Snort ruleset"""
        rules = []
        
        for line_num, line in enumerate(content.split('\n'), 1):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # Parse Suricata rule
            if line.startswith(('alert', 'log', 'pass', 'drop', 'reject', 'sdrop')):
                rule_data = self._parse_suricata_rule(line, line_num)
                if rule_data:
                    rules.append(rule_data)
        
        logger.info(f"Parsed {len(rules)} Suricata rules")
        return rules

    def _parse_suricata_rule(self, rule_line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse a single Suricata rule"""
        # Basic pattern to extract action and protocol
        basic_match = re.match(r'^(\w+)\s+(\w+)\s+', rule_line)
        if not basic_match:
            return None
        
        action = basic_match.group(1)
        protocol = basic_match.group(2)
        
        # Extract message
        msg_match = re.search(r'msg:\s*"([^"]+)"', rule_line)
        msg = msg_match.group(1) if msg_match else f"Rule {line_num}"
        
        # Extract CrowdStrike specific metadata
        cs_id = None
        cs_id_match = re.search(r'\[(CS[A-Z]{1,2}-\d+)\]', msg)
        if cs_id_match:
            cs_id = cs_id_match.group(1)
        
        # Extract sid
        sid_match = re.search(r'sid:(\d+)', rule_line)
        sid = sid_match.group(1) if sid_match else None
        
        # Extract reference
        ref_match = re.search(r'reference:([^;]+)', rule_line)
        reference = ref_match.group(1).strip() if ref_match else None
        
        # Extract classtype
        classtype_match = re.search(r'classtype:\s*([^;]+)', rule_line)
        classtype = classtype_match.group(1).strip() if classtype_match else None
        
        # Generate rule ID
        if sid:
            rule_id = f"cs_sid_{sid}"
        else:
            rule_hash = generate_rule_hash(rule_line)
            rule_id = f"cs_suricata_{rule_hash[:12]}"
        
        return {
            'rule_id': rule_id,
            'name': msg,
            'description': msg,
            'raw_rule': rule_line,
            'rule_format': 'suricata',
            'action': action,
            'protocol': protocol,
            'sid': sid,
            'cs_id': cs_id,
            'reference': reference,
            'classtype': classtype
        }

    def _extract_metadata_for_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build comprehensive metadata for a rule"""
        rule_format = rule_data.get('rule_format')
        
        metadata = {
            'rule_format': rule_format,
            'source_type': 'crowdstrike',
            'processor_version': '4.0_complete_rewrite',
            'needs_enrichment': True,
            'siem_platform': 'CrowdStrike Falcon',
            'source_org': 'CrowdStrike',
        }
        
        if rule_format == 'yara':
            # YARA-specific metadata
            yara_meta = rule_data.get('metadata', {})
            
            metadata.update({
                'author': yara_meta.get('copyright', 'CrowdStrike Inc.'),
                'language': 'yara',
                'aor': 'Endpoint',
                'data_sources': ['File Analysis', 'Memory Analysis', 'Process Monitoring'],
                'version': yara_meta.get('version'),
                'last_modified': yara_meta.get('last_modified'),
                'actor': yara_meta.get('actor'),
                'malware_family': yara_meta.get('malware_family'),
                'reports': yara_meta.get('reports'),
                'info_controls': 'TLP:WHITE'
            })
            
            # Extract hunt ID from reports field
            if yara_meta.get('reports'):
                metadata['hunt_id'] = yara_meta['reports']
            
        elif rule_format == 'suricata':
            # Suricata-specific metadata
            metadata.update({
                'author': 'CrowdStrike Inc.',
                'language': 'suricata',
                'aor': 'Network Perimeter',
                'data_sources': self._get_data_sources_for_protocol(rule_data.get('protocol')),
                'action': rule_data.get('action'),
                'protocol': rule_data.get('protocol'),
                'sid': rule_data.get('sid'),
                'classtype': rule_data.get('classtype'),
                'info_controls': 'TLP:WHITE'
            })
            
            # Extract hunt ID from CS ID
            if rule_data.get('cs_id'):
                metadata['hunt_id'] = rule_data['cs_id']
            
            # Parse reference URL
            if rule_data.get('reference'):
                ref = rule_data['reference']
                if ref.startswith('url,'):
                    ref = ref[4:]
                metadata['references'] = [ref]
        
        # Extract threat actor and malware from rule name/description
        self._extract_threat_intel(rule_data, metadata)
        
        return metadata

    def _get_data_sources_for_protocol(self, protocol: str) -> List[str]:
        """Map protocol to data sources"""
        protocol = (protocol or '').lower()
        
        mappings = {
            'tcp': ['Network Traffic', 'TCP Connections'],
            'udp': ['Network Traffic', 'UDP Traffic'],
            'http': ['Web Traffic', 'HTTP Logs'],
            'https': ['Web Traffic', 'HTTPS Logs'],
            'dns': ['DNS Logs', 'DNS Traffic'],
            'smtp': ['Email Gateway', 'SMTP Traffic'],
            'icmp': ['Network Traffic', 'ICMP Traffic'],
            'ip': ['Network Traffic', 'IP Traffic']
        }
        
        return mappings.get(protocol, ['Network Traffic'])

    def _extract_threat_intel(self, rule_data: Dict[str, Any], metadata: Dict[str, Any]):
        """Extract threat actor and malware family from rule content"""
        combined_text = f"{rule_data.get('name', '')} {rule_data.get('description', '')}".upper()
        
        # CrowdStrike adversary patterns
        adversary_patterns = [
            r'\b([A-Z]+[\s_](?:SPIDER|BEAR|KITTEN|PANDA|TIGER|JACKAL|HAWK|EAGLE|CROW))\b',
            r'\b(APT\s?\d{1,3})\b',
            r'\b(FIN\d{1,2})\b',
            r'\b(UNC\d{3,4})\b'
        ]
        
        for pattern in adversary_patterns:
            match = re.search(pattern, combined_text)
            if match and not metadata.get('actor'):
                metadata['intrusion_set'] = match.group(1).replace('_', ' ').title()
                break
        
        # Common malware families
        if not metadata.get('malware_family'):
            malware_keywords = [
                'COBALT STRIKE', 'EMOTET', 'TRICKBOT', 'QAKBOT', 'ICEDID',
                'RYUK', 'CONTI', 'LOCKBIT', 'REVIL', 'DARKSIDE', 'BLACKCAT',
                'DERUSBI', 'MINIASP', 'PHANTOMBOT', 'ELDORADO', 'CORETECH'
            ]
            
            for malware in malware_keywords:
                if malware in combined_text:
                    metadata['malware_family'] = malware.title().replace(' ', '')
                    break

    def _build_tags(self, rule_data: Dict[str, Any], metadata: Dict[str, Any]) -> List[str]:
        """Build tags for the rule"""
        tags = ['source:crowdstrike']
        
        # Format tag
        rule_format = rule_data.get('rule_format', 'unknown')
        tags.append(f"format:{rule_format}")
        
        # YARA tags from rule declaration
        if rule_format == 'yara' and rule_data.get('tags'):
            for tag in rule_data['tags']:
                tags.append(f"yara:{tag}")
        
        # Suricata action and protocol
        if rule_format == 'suricata':
            if rule_data.get('action'):
                tags.append(f"action:{rule_data['action']}")
            if rule_data.get('protocol'):
                tags.append(f"protocol:{rule_data['protocol']}")
            if rule_data.get('classtype'):
                tags.append(f"classtype:{rule_data['classtype']}")
        
        # Threat intel tags
        if metadata.get('malware_family'):
            tags.append(f"malware:{metadata['malware_family'].lower()}")
        if metadata.get('intrusion_set'):
            tags.append(f"actor:{metadata['intrusion_set'].lower().replace(' ', '_')}")
        if metadata.get('actor'):
            tags.append(f"actor:{metadata['actor'].lower().replace(' ', '_')}")
        
        return tags

    def process_rules(self, rules: List[Dict[str, Any]], source_id: int):
        """Process parsed rules into the database"""
        with db_session() as session:
            rule_repo = RuleRepository(session)
            
            for rule_data in rules:
                self.processed_count += 1
                
                try:
                    rule_id = rule_data['rule_id']
                    rule_content = rule_data['raw_rule']
                    rule_hash = generate_rule_hash(rule_content)
                    
                    # Build metadata and tags
                    metadata = self._extract_metadata_for_rule(rule_data)
                    tags = self._build_tags(rule_data, metadata)
                    
                    rule_payload = {
                        'name': rule_data['name'],
                        'description': rule_data['description'],
                        'rule_content': rule_content,
                        'rule_type': rule_data['rule_format'],
                        'severity': self._determine_severity(rule_data, metadata),
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
                    logger.error(f"Failed to process rule {rule_data.get('rule_id')}: {e}")

    def _determine_severity(self, rule_data: Dict[str, Any], metadata: Dict[str, Any]) -> str:
        """Determine rule severity based on content"""
        # Check for ransomware or destructive malware
        high_severity_indicators = ['ransomware', 'wiper', 'destructive', 'apt']
        name_lower = rule_data.get('name', '').lower()
        
        for indicator in high_severity_indicators:
            if indicator in name_lower:
                return 'high'
        
        # Check Suricata action
        if rule_data.get('action') in ['drop', 'reject']:
            return 'high'
        
        # Check for specific threat actors
        if metadata.get('intrusion_set') or metadata.get('actor'):
            return 'high'
        
        return 'medium'

    def process_s3_object(self, bucket: str, key: str):
        """Process S3 object containing CrowdStrike rules"""
        logger.info(f"Processing S3 object: s3://{bucket}/{key}")
        
        try:
            # Download file from S3
            s3_object = s3_client.get_object(Bucket=bucket, Key=key)
            content = s3_object['Body'].read().decode('utf-8')
            
            # Determine file type
            key_lower = key.lower()
            
            if 'yara' in key_lower:
                rules = self.parse_yara_file(content)
            elif 'snort' in key_lower or 'suricata' in key_lower:
                rules = self.parse_suricata_file(content)
            else:
                logger.warning(f"Unknown file type for {key}")
                return
            
            # Get source ID before session closes
            with db_session() as session:
                source = self.get_or_create_source(session)
                source_id = source.id
                session.commit()
                
            self.process_rules(rules, source_id)
            
            # Trigger enrichment
            if self.processed_rule_ids:
                self._trigger_enrichment(source.id, self.processed_rule_ids)
                
        except Exception as e:
            logger.error(f"Fatal error processing {key}: {e}", exc_info=True)
            self.error_count += 1
        
        logger.info(
            f"Processing complete - Created: {self.created_count}, "
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
                'processor_version': '4.0_complete_rewrite'
            }
            
            lambda_client.invoke(
                FunctionName='saint-enrichment-orchestrator',
                InvocationType='Event',
                Payload=json.dumps(payload)
            )
            
            logger.info(f"Triggered enrichment for {len(rule_ids)} rules")
            
        except Exception as e:
            logger.error(f"Failed to trigger enrichment: {e}")


def lambda_handler(event, context):
    """Lambda handler for S3 events"""
    processor = CrowdStrikeProcessor()
    
    try:
        for record in event.get('Records', []):
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']
            
            if key.startswith('crowdstrike/'):
                processor.process_s3_object(bucket, key)
            else:
                logger.warning(f"Skipping file not in crowdstrike/ folder: {key}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Processing complete',
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