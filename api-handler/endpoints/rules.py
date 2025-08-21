# endpoints/rules.py
"""
API endpoints for rules
"""

import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from sqlalchemy import func, and_, or_, desc, asc, text, exists
from sqlalchemy.orm import joinedload, selectinload, subqueryload

from saint_datamodel import db_session
from saint_datamodel.models import (
    DetectionRule, RuleSource, MitreTechnique, MitreTactic, CveEntry,
    RuleMitreMapping, RuleCveMapping
)
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)

def search_rules(params: Dict[str, Any]) -> Dict[str, Any]:
    """Search rules using actual mapping tables"""
    try:
        search_params = validate_search_params(params)
        
        with db_session() as session:
            # Build query with eager loading of relationships
            query = session.query(DetectionRule).options(
                joinedload(DetectionRule.source),
                selectinload(DetectionRule.mitre_mappings).joinedload(RuleMitreMapping.technique),
                selectinload(DetectionRule.cve_mappings).joinedload(RuleCveMapping.cve)
            ).distinct()
            
            # Apply filters
            query = apply_search_filters(query, search_params)
            
            # Get total before pagination
            total_count = query.count()
            
            # Apply sorting
            query = apply_sorting(query, search_params)
            
            # Apply pagination
            query = query.offset(search_params['offset']).limit(search_params['limit'])
            rules = query.all()
            
            # Serialize rules with actual mapping data
            serialized_rules = []
            for rule in rules:
                try:
                    # Get actual MITRE techniques from mappings
                    mitre_technique_ids = [m.technique.technique_id for m in rule.mitre_mappings if m.technique]
                    
                    # Get actual CVEs from mappings
                    cve_ids = [m.cve.cve_id for m in rule.cve_mappings if m.cve]
                    
                    # Extract platforms from metadata
                    platforms = []
                    if rule.rule_metadata:
                        platforms = rule.rule_metadata.get('rule_platforms', [])
                    
                    rule_data = {
                        'id': str(rule.id),
                        'source_rule_id': rule.rule_id,
                        'title': rule.name,
                        'description': rule.description[:500] + '...' if rule.description and len(rule.description) > 500 else rule.description,
                        'rule_type': rule.rule_type,
                        'severity': rule.severity or 'unknown',
                        'status': 'active' if rule.is_active else 'inactive',
                        'tags': rule.tags or [],
                        'platforms': platforms,
                        'rule_platforms': platforms,  # Same as platforms for now
                        'created_date': rule.created_date.isoformat() if rule.created_date else None,
                        'modified_date': rule.updated_date.isoformat() if rule.updated_date else None,
                        'rule_source': rule.source.name if rule.source else rule.rule_type or '',
                        
                        # Use actual mapping data
                        'has_mitre_mapping': len(mitre_technique_ids) > 0,
                        'has_cve_references': len(cve_ids) > 0,
                        'enrichment_score': calculate_enrichment_score(rule, len(mitre_technique_ids), len(cve_ids)),
                        'linked_technique_ids': mitre_technique_ids,
                        
                        # Include counts for debugging
                        'extracted_mitre_count': len(mitre_technique_ids),
                        'extracted_cve_count': len(cve_ids)
                    }
                    
                    serialized_rules.append(rule_data)
                    
                except Exception as e:
                    logger.error(f"Error serializing rule {rule.id}: {e}")
                    continue
            
            response_data = {
                'rules': serialized_rules,
                'total': total_count,
                'offset': search_params['offset'],
                'limit': search_params['limit'],
                'page': (search_params['offset'] // search_params['limit']) + 1,
                'totalPages': (total_count + search_params['limit'] - 1) // search_params['limit'],
                'has_more': (search_params['offset'] + search_params['limit']) < total_count
            }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error searching rules: {e}", exc_info=True)
        return create_error_response(500, f"Failed to search rules: {str(e)}")

def apply_search_filters(query, params: Dict[str, Any]):
    """Apply search filters using mapping tables"""
    
    # Text search
    if params.get('query'):
        search_term = f"%{params['query']}%"
        query = query.filter(
            or_(
                DetectionRule.name.ilike(search_term),
                DetectionRule.description.ilike(search_term),
                DetectionRule.rule_id.ilike(search_term)
            )
        )
    
    # Basic filters
    if params.get('rule_types'):
        query = query.filter(DetectionRule.rule_type.in_(params['rule_types']))
    
    if params.get('severities'):
        query = query.filter(DetectionRule.severity.in_(params['severities']))
    
    if params.get('is_active') is not None:
        query = query.filter(DetectionRule.is_active == params['is_active'])
    
    # MITRE technique filter using mapping table
    if params.get('mitre_techniques'):
        subq = session.query(RuleMitreMapping.rule_id).join(
            MitreTechnique
        ).filter(
            MitreTechnique.technique_id.in_(params['mitre_techniques'])
        ).subquery()
        
        query = query.filter(DetectionRule.id.in_(subq))
    
    # CVE filter using mapping table
    if params.get('cve_ids'):
        subq = session.query(RuleCveMapping.rule_id).join(
            CveEntry
        ).filter(
            CveEntry.cve_id.in_(params['cve_ids'])
        ).subquery()
        
        query = query.filter(DetectionRule.id.in_(subq))
    
    # Has MITRE filter using EXISTS
    if params.get('has_mitre') is not None:
        if params['has_mitre']:
            query = query.filter(
                exists().where(RuleMitreMapping.rule_id == DetectionRule.id)
            )
        else:
            query = query.filter(
                ~exists().where(RuleMitreMapping.rule_id == DetectionRule.id)
            )
    
    # Has CVE filter using EXISTS
    if params.get('has_cves') is not None:
        if params['has_cves']:
            query = query.filter(
                exists().where(RuleCveMapping.rule_id == DetectionRule.id)
            )
        else:
            query = query.filter(
                ~exists().where(RuleCveMapping.rule_id == DetectionRule.id)
            )
    
    return query

def apply_sorting(query, params: Dict[str, Any]):
    """Apply sorting with field mapping"""
    sort_field_map = {
        'title': 'name',
        'modified_date': 'updated_date',
        'severity': 'severity',
        'created_date': 'created_date',
        'rule_type': 'rule_type'
    }
    
    sort_by = sort_field_map.get(params.get('sort_by'), 'updated_date')
    sort_field = getattr(DetectionRule, sort_by, DetectionRule.updated_date)
    
    if params['sort_dir'] == 'desc':
        return query.order_by(desc(sort_field))
    else:
        return query.order_by(asc(sort_field))

def calculate_enrichment_score(rule, mitre_count: int, cve_count: int) -> float:
    """Calculate enrichment score based on actual mappings"""
    score = 0.0
    
    # MITRE mappings (40%)
    if mitre_count > 0:
        score += min(mitre_count * 10, 40)
    
    # CVE mappings (30%)
    if cve_count > 0:
        score += min(cve_count * 10, 30)
    
    # Tags (10%)
    if rule.tags and len(rule.tags) > 0:
        score += min(len(rule.tags) * 2, 10)
    
    # Description quality (10%)
    if rule.description and len(rule.description) > 100:
        score += 10
    
    # Metadata presence (10%)
    if rule.rule_metadata and len(rule.rule_metadata) > 2:
        score += 10
    
    return min(score, 100.0)

def get_rule_details(rule_id: str) -> Dict[str, Any]:
    """Get detailed rule with full relationship data"""
    try:
        # Parse ID
        try:
            db_id = int(rule_id)
            id_filter = DetectionRule.id == db_id
        except ValueError:
            id_filter = DetectionRule.rule_id == rule_id
        
        with db_session() as session:
            # Eager load all relationships
            rule = session.query(DetectionRule).options(
                joinedload(DetectionRule.source),
                selectinload(DetectionRule.mitre_mappings).joinedload(RuleMitreMapping.technique),
                selectinload(DetectionRule.cve_mappings).joinedload(RuleCveMapping.cve)
            ).filter(id_filter).first()
            
            if not rule:
                return create_error_response(404, f"Rule not found: {rule_id}")
            
            # Build MITRE technique details
            mitre_techniques = []
            linked_technique_ids = []
            for mapping in rule.mitre_mappings:
                if mapping.technique:
                    linked_technique_ids.append(mapping.technique.technique_id)
                    mitre_techniques.append({
                        'technique_id': mapping.technique.technique_id,
                        'name': mapping.technique.name,
                        'description': mapping.technique.description,
                        'confidence': float(mapping.mapping_confidence) if mapping.mapping_confidence else 1.0
                    })
            
            # Build CVE details
            cve_references = []
            for mapping in rule.cve_mappings:
                if mapping.cve:
                    cve_references.append({
                        'cve_id': mapping.cve.cve_id,
                        'description': mapping.cve.description,
                        'severity': mapping.cve.severity,
                        'cvss_score': float(mapping.cve.cvss_v3_score) if mapping.cve.cvss_v3_score else None
                    })
            
            # Extract platforms
            platforms = []
            if rule.rule_metadata:
                platforms = rule.rule_metadata.get('rule_platforms', [])
            
            # Build response
            rule_detail = {
                'id': str(rule.id),
                'source_rule_id': rule.rule_id,
                'title': rule.name,
                'description': rule.description,
                'author': rule.rule_metadata.get('author') if rule.rule_metadata else None,
                'severity': rule.severity or 'unknown',
                'status': 'active' if rule.is_active else 'inactive',
                'rule_type': rule.rule_type,
                'rule_source': rule.source.name if rule.source else rule.rule_type or '',
                'platforms': platforms,
                'rule_platforms': platforms,
                'tags': rule.tags or [],
                'created_date': rule.created_date.isoformat() if rule.created_date else None,
                'modified_date': rule.updated_date.isoformat() if rule.updated_date else None,
                
                # Enrichment data from actual mappings
                'has_mitre_mapping': len(mitre_techniques) > 0,
                'has_cve_references': len(cve_references) > 0,
                'enrichment_score': calculate_enrichment_score(rule, len(mitre_techniques), len(cve_references)),
                'linked_technique_ids': linked_technique_ids,
                'linked_techniques': mitre_techniques,  # Full technique objects
                
                # Raw content
                'raw_rule': None,  # Not stored in DB
                'rule_content': rule.rule_content,
                'rule_metadata': rule.rule_metadata,
                'source_file_path': None,  # Not stored in DB
                
                # Type-specific details from metadata
                'elastic_details': rule.rule_metadata.get('elastic_details') if rule.rule_metadata else None,
                'sentinel_details': rule.rule_metadata.get('sentinel_details') if rule.rule_metadata else None,
                'trinitycyber_details': rule.rule_metadata.get('trinitycyber_details') if rule.rule_metadata else None,
                
                # Actual relationship data
                'mitre_techniques': mitre_techniques,
                'cve_references': cve_references,
                'related_rules': []  # Would need similarity query
            }
            
            return create_api_response(200, rule_detail)
            
    except Exception as e:
        logger.error(f"Error getting rule details: {e}", exc_info=True)
        return create_error_response(500, f"Failed to get rule details: {str(e)}")

def validate_search_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and sanitize parameters"""
    validated = {}
    
    validated['query'] = params.get('query', '').strip()[:500] if params.get('query') else None
    validated['offset'] = max(0, int(params.get('offset', 0)))
    validated['limit'] = min(max(1, int(params.get('limit', 100))), 1000)
    validated['sort_by'] = params.get('sort_by', 'updated_date')
    validated['sort_dir'] = 'desc' if params.get('sort_dir') == 'desc' else 'asc'
    
    # Array filters
    for filter_name in ['rule_types', 'severities', 'mitre_techniques', 'cve_ids']:
        value = params.get(filter_name)
        if value:
            if isinstance(value, str):
                validated[filter_name] = value.split(',') if ',' in value else [value]
            elif isinstance(value, list):
                validated[filter_name] = value[:50]
    
    # Boolean filters
    for bool_filter in ['has_mitre', 'has_cves', 'is_active']:
        if params.get(bool_filter) is not None:
            value = params[bool_filter]
            validated[bool_filter] = str(value).lower() in ['true', '1', 'yes']
    
    return validated