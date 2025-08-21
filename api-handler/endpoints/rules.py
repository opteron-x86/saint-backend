# endpoints/rules.py
"""
API endpoints for rules with complete filter implementation
"""

import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from sqlalchemy import func, and_, or_, desc, asc, text, exists
from sqlalchemy.orm import joinedload, selectinload, subqueryload, Session

from saint_datamodel import db_session
from saint_datamodel.models import (
    DetectionRule, RuleSource, MitreTechnique, MitreTactic, CveEntry,
    RuleMitreMapping, RuleCveMapping
)
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)

def search_rules(params: Dict[str, Any]) -> Dict[str, Any]:
    """Search rules with complete filter support"""
    try:
        search_params = validate_search_params(params)
        
        with db_session() as session:
            # Build base query with eager loading
            query = session.query(DetectionRule).options(
                joinedload(DetectionRule.source),
                selectinload(DetectionRule.mitre_mappings).joinedload(RuleMitreMapping.technique),
                selectinload(DetectionRule.cve_mappings).joinedload(RuleCveMapping.cve)
            ).distinct()
            
            # Apply all filters
            query = apply_search_filters(session, query, search_params)
            
            # Get total count before pagination
            total_count = query.count()
            
            # Apply sorting
            query = apply_sorting(query, search_params)
            
            # Apply pagination
            query = query.offset(search_params['offset']).limit(search_params['limit'])
            rules = query.all()
            
            # Serialize rules
            serialized_rules = []
            for rule in rules:
                try:
                    mitre_technique_ids = [m.technique.technique_id for m in rule.mitre_mappings if m.technique]
                    cve_ids = [m.cve.cve_id for m in rule.cve_mappings if m.cve]
                    
                    platforms = []
                    if rule.rule_metadata:
                        platforms = rule.rule_metadata.get('rule_platforms', [])
                    
                    rule_data = {
                        'id': str(rule.id),
                        'rule_id': rule.rule_id,
                        'name': rule.name,
                        'description': rule.description,
                        'severity': rule.severity,
                        'rule_type': rule.rule_type,
                        'rule_source': rule.source.name if rule.source else None,
                        'rule_source_id': rule.source_id,
                        'created_date': rule.created_date.isoformat() if rule.created_date else None,
                        'modified_date': rule.updated_date.isoformat() if rule.updated_date else None,
                        'is_active': rule.is_active,
                        'confidence_score': float(rule.confidence_score) if rule.confidence_score else None,
                        'false_positive_rate': float(rule.false_positive_rate) if rule.false_positive_rate else None,
                        'mitre_techniques': mitre_technique_ids,
                        'cve_ids': cve_ids,
                        'platforms': platforms,
                        'tags': rule.tags if rule.tags else [],
                        'has_mitre': len(mitre_technique_ids) > 0,
                        'has_cves': len(cve_ids) > 0,
                        'rule_metadata': rule.rule_metadata or {}
                    }
                    serialized_rules.append(rule_data)
                except Exception as e:
                    logger.error(f"Error serializing rule {rule.id}: {e}")
                    continue
            
            return create_api_response(200, {
                'items': serialized_rules,
                'total': total_count,
                'offset': search_params['offset'],
                'limit': search_params['limit']
            })
            
    except Exception as e:
        logger.error(f"Error searching rules: {e}", exc_info=True)
        return create_error_response(500, f"Failed to search rules: {str(e)}")

def apply_search_filters(session: Session, query, params: Dict[str, Any]):
    """Apply all search filters with proper implementation"""
    
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
    
    # Severity filter - now expects 'severity' array
    if params.get('severity'):
        query = query.filter(DetectionRule.severity.in_(params['severity']))
    
    # Active status filter
    if params.get('is_active') is not None:
        query = query.filter(DetectionRule.is_active == params['is_active'])
    
    # Rule source filter
    if params.get('rule_source'):
        source_ids = [int(sid) for sid in params['rule_source'] if str(sid).isdigit()]
        if source_ids:
            query = query.filter(DetectionRule.source_id.in_(source_ids))
    
    # MITRE technique filter using mapping table
    if params.get('mitre_techniques'):
        technique_subq = (
            session.query(RuleMitreMapping.rule_id)
            .join(MitreTechnique)
            .filter(MitreTechnique.technique_id.in_(params['mitre_techniques']))
            .subquery()
        )
        query = query.filter(DetectionRule.id.in_(technique_subq))
    
    # MITRE platforms filter (platforms from MITRE techniques)
    if params.get('platforms'):
        platform_subq = (
            session.query(RuleMitreMapping.rule_id)
            .join(MitreTechnique)
            .filter(
                or_(*[
                    MitreTechnique.platforms.op('@>')([platform])
                    for platform in params['platforms']
                ])
            )
            .subquery()
        )
        query = query.filter(DetectionRule.id.in_(platform_subq))
    
    # Rule platforms filter (platforms from rule metadata)
    if params.get('rule_platform'):
        platform_conditions = []
        for platform in params['rule_platform']:
            platform_conditions.append(
                DetectionRule.rule_metadata['rule_platforms'].op('@>')([platform])
            )
        if platform_conditions:
            query = query.filter(or_(*platform_conditions))
    
    # MITRE tactics filter
    if params.get('tactics'):
        tactics_subq = (
            session.query(RuleMitreMapping.rule_id)
            .join(MitreTechnique)
            .join(MitreTactic, MitreTechnique.tactic_id == MitreTactic.id)
            .filter(MitreTactic.name.in_(params['tactics']))
            .subquery()
        )
        query = query.filter(DetectionRule.id.in_(tactics_subq))
    
    # CVE filter using mapping table
    if params.get('cve_ids'):
        cve_subq = (
            session.query(RuleCveMapping.rule_id)
            .join(CveEntry)
            .filter(CveEntry.cve_id.in_(params['cve_ids']))
            .subquery()
        )
        query = query.filter(DetectionRule.id.in_(cve_subq))
    
    # Has MITRE filter
    if params.get('has_mitre') is not None:
        if params['has_mitre']:
            query = query.filter(
                exists().where(RuleMitreMapping.rule_id == DetectionRule.id)
            )
        else:
            query = query.filter(
                ~exists().where(RuleMitreMapping.rule_id == DetectionRule.id)
            )
    
    # Has CVE filter
    if params.get('has_cves') is not None:
        if params['has_cves']:
            query = query.filter(
                exists().where(RuleCveMapping.rule_id == DetectionRule.id)
            )
        else:
            query = query.filter(
                ~exists().where(RuleCveMapping.rule_id == DetectionRule.id)
            )
    
    # Tags filter
    if params.get('tags'):
        tag_conditions = []
        for tag in params['tags']:
            tag_conditions.append(DetectionRule.tags.op('@>')([tag]))
        if tag_conditions:
            query = query.filter(or_(*tag_conditions))
    
    # Date range filter
    if params.get('start_date'):
        query = query.filter(DetectionRule.updated_date >= params['start_date'])
    if params.get('end_date'):
        query = query.filter(DetectionRule.updated_date <= params['end_date'])
    
    return query

def apply_sorting(query, params: Dict[str, Any]):
    """Apply sorting to query"""
    sort_by = params.get('sort_by', 'updated_date')
    sort_dir = params.get('sort_dir', 'desc')
    
    # Map sort fields to model attributes
    sort_fields = {
        'name': DetectionRule.name,
        'severity': DetectionRule.severity,
        'created_date': DetectionRule.created_date,
        'updated_date': DetectionRule.updated_date,
        'modified_date': DetectionRule.updated_date,
        'confidence_score': DetectionRule.confidence_score,
        'false_positive_rate': DetectionRule.false_positive_rate
    }
    
    sort_column = sort_fields.get(sort_by, DetectionRule.updated_date)
    
    if sort_dir == 'desc':
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(asc(sort_column))
    
    return query

def get_rule_details(rule_id: str) -> Dict[str, Any]:
    """Get detailed rule information with all relationships"""
    try:
        with db_session() as session:
            # Try by ID first
            rule = None
            if rule_id.isdigit():
                rule = session.query(DetectionRule).options(
                    joinedload(DetectionRule.source),
                    selectinload(DetectionRule.mitre_mappings).joinedload(RuleMitreMapping.technique),
                    selectinload(DetectionRule.cve_mappings).joinedload(RuleCveMapping.cve)
                ).filter(DetectionRule.id == int(rule_id)).first()
            
            # Try by rule_id if not found
            if not rule:
                rule = session.query(DetectionRule).options(
                    joinedload(DetectionRule.source),
                    selectinload(DetectionRule.mitre_mappings).joinedload(RuleMitreMapping.technique),
                    selectinload(DetectionRule.cve_mappings).joinedload(RuleCveMapping.cve)
                ).filter(DetectionRule.rule_id == rule_id).first()
            
            if not rule:
                return create_error_response(404, f"Rule {rule_id} not found")
            
            # Build MITRE techniques data
            mitre_techniques = []
            for mapping in rule.mitre_mappings:
                if mapping.technique:
                    tech = mapping.technique
                    mitre_techniques.append({
                        'technique_id': tech.technique_id,
                        'name': tech.name,
                        'description': tech.description,
                        'platforms': tech.platforms or [],
                        'tactic': {
                            'name': tech.tactic.name if tech.tactic else None,
                            'description': tech.tactic.description if tech.tactic else None
                        } if tech.tactic_id else None
                    })
            
            # Build CVE references
            cve_references = []
            for mapping in rule.cve_mappings:
                if mapping.cve:
                    cve = mapping.cve
                    cve_references.append({
                        'cve_id': cve.cve_id,
                        'description': cve.description,
                        'severity': cve.severity,
                        'cvss_v3_score': float(cve.cvss_v3_score) if cve.cvss_v3_score else None
                    })
            
            rule_detail = {
                'id': str(rule.id),
                'rule_id': rule.rule_id,
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'rule_type': rule.rule_type,
                'rule_source': rule.source.name if rule.source else None,
                'rule_source_id': rule.source_id,
                'created_date': rule.created_date.isoformat() if rule.created_date else None,
                'modified_date': rule.updated_date.isoformat() if rule.updated_date else None,
                'is_active': rule.is_active,
                'confidence_score': float(rule.confidence_score) if rule.confidence_score else None,
                'false_positive_rate': float(rule.false_positive_rate) if rule.false_positive_rate else None,
                'tags': rule.tags or [],
                'rule_content': rule.rule_content,
                'rule_metadata': rule.rule_metadata,
                'mitre_techniques': mitre_techniques,
                'cve_references': cve_references,
                'related_rules': []
            }
            
            return create_api_response(200, rule_detail)
            
    except Exception as e:
        logger.error(f"Error getting rule details: {e}", exc_info=True)
        return create_error_response(500, f"Failed to get rule details: {str(e)}")

def validate_search_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and transform search parameters to match frontend contract"""
    validated = {}
    
    # Text search
    validated['query'] = params.get('query', '').strip()[:500] if params.get('query') else None
    
    # Pagination
    validated['offset'] = max(0, int(params.get('offset', 0)))
    validated['limit'] = min(max(1, int(params.get('limit', 100))), 1000)
    
    # Sorting
    validated['sort_by'] = params.get('sort_by', 'updated_date')
    validated['sort_dir'] = 'desc' if params.get('sort_dir') == 'desc' else 'asc'
    
    # Array filters - handle both comma-separated strings and arrays
    array_filters = [
        'severity',           # Changed from 'severities'
        'platforms',          # MITRE platforms
        'rule_platform',      # Rule platforms
        'tactics',            # MITRE tactics
        'rule_source',        # Rule sources
        'tags',               # Tags
        'mitre_techniques',   # MITRE technique IDs
        'cve_ids'            # CVE IDs
    ]
    
    for filter_name in array_filters:
        value = params.get(filter_name)
        if value:
            if isinstance(value, str):
                validated[filter_name] = value.split(',') if ',' in value else [value]
            elif isinstance(value, list):
                validated[filter_name] = value[:50]  # Limit array size
    
    # Boolean filters
    for bool_filter in ['has_mitre', 'has_cves', 'is_active']:
        if params.get(bool_filter) is not None:
            value = params[bool_filter]
            validated[bool_filter] = str(value).lower() in ['true', '1', 'yes']
    
    # Date range filters
    if params.get('start_date'):
        validated['start_date'] = params['start_date']
    if params.get('end_date'):
        validated['end_date'] = params['end_date']
    
    return validated

def get_enrichment_stats(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get enrichment statistics for rules"""
    try:
        with db_session() as session:
            # Total rules
            total_rules = session.query(func.count(DetectionRule.id)).scalar()
            
            # Rules with MITRE mappings
            rules_with_mitre = session.query(
                func.count(func.distinct(RuleMitreMapping.rule_id))
            ).scalar()
            
            # Rules with CVE mappings
            rules_with_cves = session.query(
                func.count(func.distinct(RuleCveMapping.rule_id))
            ).scalar()
            
            # Total unique techniques covered
            unique_techniques = session.query(
                func.count(func.distinct(RuleMitreMapping.technique_id))
            ).scalar()
            
            # Total unique CVEs referenced
            unique_cves = session.query(
                func.count(func.distinct(RuleCveMapping.cve_id))
            ).scalar()
            
            stats = {
                'total_rules': total_rules,
                'rules_with_mitre': rules_with_mitre,
                'rules_with_cves': rules_with_cves,
                'mitre_coverage_percentage': round((rules_with_mitre / total_rules * 100) if total_rules > 0 else 0, 2),
                'cve_coverage_percentage': round((rules_with_cves / total_rules * 100) if total_rules > 0 else 0, 2),
                'unique_techniques_covered': unique_techniques,
                'unique_cves_referenced': unique_cves
            }
            
            return create_api_response(200, stats)
            
    except Exception as e:
        logger.error(f"Error getting enrichment stats: {e}", exc_info=True)
        return create_error_response(500, "Failed to get enrichment statistics")

def export_rules(params: Dict[str, Any]) -> Dict[str, Any]:
    """Export rules in various formats"""
    # Implementation for export functionality
    return create_api_response(501, {"message": "Export functionality not yet implemented"})