# mitre_enricher.py
"""
SAINT MITRE Enricher Lambda
"""
import json
import logging
import re
from typing import Set, List, Dict, Any, Tuple, Optional
from datetime import datetime

from saint_datamodel import db_session
from saint_datamodel.models import DetectionRule, MitreTechnique, RuleMitreMapping

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class MitreEnricher:
    TECHNIQUE_ID_PATTERN = re.compile(r'T(\d{4})(?:\.(\d{3}))?', re.IGNORECASE)
    
    # Common MITRE technique patterns in rule content
    TECHNIQUE_PATTERNS = {
        'explicit_id': re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.IGNORECASE),
        'mitre_reference': re.compile(r'mitre.*att&ck.*T\d{4}', re.IGNORECASE),
        'attack_reference': re.compile(r'att&ck.*T\d{4}', re.IGNORECASE),
        'technique_context': re.compile(r'technique\s+T\d{4}', re.IGNORECASE)
    }
        
    def __init__(self):
        self.processed_count = 0
        self.mappings_created = 0
        self.mappings_updated = 0
        self.techniques_found = 0
        self.confidence_scores = []
        self._technique_cache = None
        self._technique_name_lookup = None
        
    def enrich_rules(self, rule_ids: List[int] = None) -> Dict[str, Any]:
        logger.info(f"Starting MITRE enrichment for {len(rule_ids) if rule_ids else 'all'} rules")
        
        with db_session() as session:
            rules = self._get_rules_to_process(session, rule_ids)
            
            if not rules:
                logger.info("No rules found for MITRE enrichment")
                return self._create_result_summary()
            
            logger.info(f"Processing {len(rules)} rules for MITRE enrichment")
            
            valid_techniques = self._load_valid_techniques(session)
            logger.info(f"Loaded {len(valid_techniques)} valid MITRE techniques")
            
            # Process rules in batches
            batch_size = 100 
            for i in range(0, len(rules), batch_size):
                batch = rules[i:i + batch_size]
                self._process_rule_batch(batch, valid_techniques, session)
                
                # Commit after each batch to avoid long transactions
                session.commit()
                
                batch_num = i//batch_size + 1
                total_batches = (len(rules)-1)//batch_size + 1
                logger.info(f"Processed batch {batch_num}/{total_batches} ({len(batch)} rules)")
                
                # If we're getting close to timeout, stop and let next invocation continue
                if batch_num >= 20:  # Process max 500 rules per invocation (20 * 25)
                    logger.info(f"Reached batch limit (500 rules). Processed {batch_num * batch_size} rules.")
                    break
            
            logger.info(f"MITRE enrichment complete: {self._create_result_summary()}")
            return self._create_result_summary()
    
    def _get_rules_to_process(self, session, rule_ids: List[int] = None) -> List[DetectionRule]:
        """Get rules that need MITRE enrichment."""
        query = session.query(DetectionRule).filter(DetectionRule.is_active == True)
        
        if rule_ids:
            query = query.filter(DetectionRule.id.in_(rule_ids))
        
        return query.all()
    
    def _load_valid_techniques(self, session) -> Dict[str, MitreTechnique]:
        """Load all valid MITRE techniques for validation AND create lookup cache."""
        # Load all techniques - no is_revoked field in your schema
        techniques = session.query(MitreTechnique).all()
        
        # Create lookup dictionary by technique_id
        technique_dict = {tech.technique_id.upper(): tech for tech in techniques}
        
        # Build efficient lookup structures for name-based matching
        self._build_technique_lookup_cache(techniques)
        
        return technique_dict
    
    def _build_technique_lookup_cache(self, techniques: List[MitreTechnique]):
        """Build efficient lookup structures for technique name matching."""
        self._technique_name_lookup = {}
        
        for technique in techniques:
            if not technique.name:
                continue
                
            technique_name_lower = technique.name.lower()
            
            # Index by exact name
            self._technique_name_lookup[technique_name_lower] = {
                'technique_id': technique.technique_id,
                'confidence': 0.8
            }
            
            # Index by key terms (only for important/common techniques)
            key_terms = {
                'process injection': technique.technique_id if 'injection' in technique_name_lower else None,
                'powershell': technique.technique_id if 'powershell' in technique_name_lower else None,
                'registry': technique.technique_id if 'registry' in technique_name_lower else None,
                'scheduled': technique.technique_id if 'scheduled' in technique_name_lower else None,
                'persistence': technique.technique_id if 'persistence' in technique_name_lower else None,
                'escalation': technique.technique_id if 'escalation' in technique_name_lower else None,
                'evasion': technique.technique_id if 'evasion' in technique_name_lower else None,
                'dumping': technique.technique_id if 'dumping' in technique_name_lower else None,
                'phishing': technique.technique_id if 'phishing' in technique_name_lower else None,
                'lateral': technique.technique_id if 'lateral' in technique_name_lower else None,
                'remote': technique.technique_id if 'remote' in technique_name_lower else None,
                'command': technique.technique_id if 'command' in technique_name_lower else None
            }
            
            for term, tech_id in key_terms.items():
                if tech_id and term not in self._technique_name_lookup:
                    self._technique_name_lookup[term] = {
                        'technique_id': tech_id,
                        'confidence': 0.6  # Lower confidence for partial matches
                    }
        
        logger.info(f"Built technique lookup cache with {len(self._technique_name_lookup)} entries")
    
    def _process_rule_batch(self, rules: List[DetectionRule], valid_techniques: Dict[str, MitreTechnique], session):
        """Process a batch of rules for MITRE enrichment."""
        for rule in rules:
            try:
                self._enrich_single_rule(rule, valid_techniques, session)
                self.processed_count += 1
            except Exception as e:
                logger.error(f"Failed to process rule {rule.id}: {e}")
    
    def _enrich_single_rule(self, rule: DetectionRule, valid_techniques: Dict[str, MitreTechnique], session):
        """Enrich a single rule with MITRE technique mappings."""
        extracted_techniques = self._extract_techniques_from_rule(rule)
        
        if not extracted_techniques:
            return
        
        self.techniques_found += len(extracted_techniques)
        
        # Create mappings for valid techniques
        for technique_info in extracted_techniques:
            technique_id = technique_info['id']
            confidence = technique_info['confidence']
            source = technique_info['source']
            
            if technique_id in valid_techniques:
                technique = valid_techniques[technique_id]
                mapping_created = self._create_or_update_mapping(
                    rule, technique, confidence, source, session
                )
                
                if mapping_created:
                    self.confidence_scores.append(confidence)
            else:
                logger.debug(f"MITRE technique {technique_id} not found in database (rule {rule.id})")
    
    def _extract_techniques_from_rule(self, rule: DetectionRule) -> List[Dict[str, Any]]:
        """Extract MITRE techniques from all rule sources."""
        techniques = []
        
        # 1. Extract from rule content (highest confidence)
        if rule.rule_content:
            content_techniques = self._extract_from_content(rule.rule_content, 'rule_content')
            techniques.extend(content_techniques)
        
        # 2. Extract from rule name (high confidence)
        if rule.name:
            name_techniques = self._extract_from_text(rule.name, 'rule_name', confidence=0.9)
            techniques.extend(name_techniques)
        
        # 3. Extract from description (medium confidence)
        if rule.description:
            desc_techniques = self._extract_from_text(rule.description, 'description', confidence=0.7)
            techniques.extend(desc_techniques)
        
        # 4. Extract from tags (medium-high confidence)
        if rule.tags:
            tag_techniques = self._extract_from_tags(rule.tags)
            techniques.extend(tag_techniques)
        
        # 5. Extract from metadata (if already exists)
        if rule.rule_metadata:
            metadata_techniques = self._extract_from_metadata(rule.rule_metadata)
            techniques.extend(metadata_techniques)
        
        # Deduplicate and return highest confidence for each technique
        return self._deduplicate_techniques(techniques)
    
    def _extract_from_content(self, content: str, source: str) -> List[Dict[str, Any]]:
        """Extract techniques from rule content with pattern matching."""
        techniques = []
        
        # Try parsing as JSON first (for structured rules)
        try:
            if content.strip().startswith('{'):
                json_data = json.loads(content)
                json_techniques = self._extract_from_json(json_data, source)
                techniques.extend(json_techniques)
        except json.JSONDecodeError:
            pass
        
        # Pattern-based extraction from text
        text_techniques = self._extract_from_text(content, source, confidence=0.8)
        techniques.extend(text_techniques)
        
        return techniques
    
    def _extract_from_json(self, json_data: Dict[str, Any], source: str) -> List[Dict[str, Any]]:
        """Extract techniques from JSON rule data."""
        techniques = []
        
        # Look for techniques in common JSON fields
        json_str = json.dumps(json_data).lower()
        
        # Direct technique ID matches
        matches = self.TECHNIQUE_ID_PATTERN.findall(json_str)
        for match in matches:
            main_id = match[0]
            sub_id = match[1] if match[1] else None
            
            technique_id = f"T{main_id}"
            if sub_id:
                technique_id += f".{sub_id}"
            
            techniques.append({
                'id': technique_id.upper(),
                'confidence': 0.9,  # High confidence for JSON content
                'source': f"{source}_json"
            })
        
        return techniques
    
    def _extract_from_text(self, text: str, source: str, confidence: float = 0.8) -> List[Dict[str, Any]]:
        """Extract techniques from text using pattern matching and cached database lookups."""
        techniques = []
        text_lower = text.lower()
        
        # 1. Direct technique ID extraction (highest confidence)
        for pattern_name, pattern in self.TECHNIQUE_PATTERNS.items():
            matches = pattern.findall(text)
            for match in matches:
                # Extract just the technique ID part
                technique_matches = self.TECHNIQUE_ID_PATTERN.findall(match)
                for tech_match in technique_matches:
                    main_id = tech_match[0]
                    sub_id = tech_match[1] if tech_match[1] else None
                    
                    technique_id = f"T{main_id}"
                    if sub_id:
                        technique_id += f".{sub_id}"
                    
                    techniques.append({
                        'id': technique_id.upper(),
                        'confidence': confidence,
                        'source': f"{source}_{pattern_name}"
                    })
        
        # 2. Fast cached technique name matching (uses prebuilt lookup)
        if self._technique_name_lookup:
            cached_techniques = self._find_techniques_using_cache(text_lower)
            for technique_info in cached_techniques:
                techniques.append({
                    'id': technique_info['technique_id'],
                    'confidence': technique_info['confidence'],
                    'source': f"{source}_cached_match"
                })
        
        return techniques
    
    def _find_techniques_using_cache(self, text: str) -> List[Dict[str, Any]]:
        """Find MITRE techniques using prebuilt cache"""
        matches = []
        
        for lookup_term, technique_info in self._technique_name_lookup.items():
            if lookup_term in text:
                matches.append({
                    'technique_id': technique_info['technique_id'],
                    'confidence': technique_info['confidence']
                })
        
        return matches
    
    def _extract_from_tags(self, tags: List[str]) -> List[Dict[str, Any]]:
        """Extract techniques from rule tags."""
        techniques = []
        
        for tag in tags:
            if isinstance(tag, str):
                # Look for MITRE-specific tags
                if 'mitre' in tag.lower() or 'att&ck' in tag.lower() or tag.startswith('T'):
                    tag_techniques = self._extract_from_text(tag, 'tags', confidence=0.85)
                    techniques.extend(tag_techniques)
        
        return techniques
    
    def _extract_from_metadata(self, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract techniques from rule metadata."""
        techniques = []
        
        # Check if metadata already has extracted techniques
        if 'extracted_mitre_techniques' in metadata:
            extracted = metadata['extracted_mitre_techniques']
            if isinstance(extracted, list):
                for technique_id in extracted:
                    techniques.append({
                        'id': technique_id.upper(),
                        'confidence': 0.95,
                        'source': 'metadata_extracted'
                    })
        
        return techniques
    
    def _deduplicate_techniques(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate techniques, keeping highest confidence for each."""
        technique_map = {}
        
        for tech in techniques:
            tech_id = tech['id']
            if tech_id not in technique_map or tech['confidence'] > technique_map[tech_id]['confidence']:
                technique_map[tech_id] = tech
        
        return list(technique_map.values())
    
    def _create_or_update_mapping(self, rule: DetectionRule, technique: MitreTechnique, 
                                confidence: float, source: str, session) -> bool:
        """Create or update rule-to-technique mapping."""
        # Check if mapping already exists
        existing_mapping = session.query(RuleMitreMapping).filter(
            RuleMitreMapping.rule_id == rule.id,
            RuleMitreMapping.technique_id == technique.id
        ).first()
        
        if existing_mapping:
            # Update if new confidence is higher
            if confidence > existing_mapping.mapping_confidence:
                existing_mapping.mapping_confidence = confidence
                existing_mapping.mapping_source = f"enrichment_layer_{source}"
                existing_mapping.updated_date = datetime.utcnow()
                self.mappings_updated += 1
                logger.debug(f"Updated mapping: Rule {rule.id} -> {technique.technique_id} (confidence: {confidence})")
                return True
        else:
            # Create new mapping
            new_mapping = RuleMitreMapping(
                rule_id=rule.id,
                technique_id=technique.id,
                mapping_source=f"enrichment_layer_{source}",
                mapping_confidence=confidence,
                created_date=datetime.utcnow(),
                updated_date=datetime.utcnow()
            )
            session.add(new_mapping)
            self.mappings_created += 1
            logger.debug(f"Created mapping: Rule {rule.id} -> {technique.technique_id} (confidence: {confidence})")
            return True
        
        return False
    
    def _create_result_summary(self) -> Dict[str, Any]:
        """Create summary of enrichment results."""
        avg_confidence = sum(self.confidence_scores) / len(self.confidence_scores) if self.confidence_scores else 0
        
        return {
            'processed_rules': self.processed_count,
            'techniques_found': self.techniques_found,
            'mappings_created': self.mappings_created,
            'mappings_updated': self.mappings_updated,
            'average_confidence': round(avg_confidence, 3),
            'total_mappings': self.mappings_created + self.mappings_updated
        }

def lambda_handler(event, context):
    """
    Lambda entry point for MITRE enrichment.
    
    Event format:
    {
        "rule_ids": [1, 2, 3, ...],  // Optional: specific rules to enrich
        "orchestrator_id": "mitre_20241201_120000"  // Optional: tracking ID
    }
    """
    enricher = MitreEnricher()
    
    try:
        rule_ids = event.get('rule_ids')
        orchestrator_id = event.get('orchestrator_id', 'manual')
        
        logger.info(f"Starting MITRE enrichment (orchestrator: {orchestrator_id})")
        
        result = enricher.enrich_rules(rule_ids)
        
        # Add metadata to result
        result.update({
            'statusCode': 200,
            'orchestrator_id': orchestrator_id,
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'MITRE enrichment completed successfully'
        })
        
        logger.info(f"MITRE enrichment complete: {result}")
        return result
        
    except Exception as e:
        error_msg = f"MITRE enrichment failed: {e}"
        logger.error(error_msg, exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e),
            'message': error_msg,
            'orchestrator_id': event.get('orchestrator_id', 'manual')
        }