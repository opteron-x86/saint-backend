# endpoints/rules.py
"""
API endpoints for detection rules with comprehensive metadata support
"""

import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict

from sqlalchemy import func, and_, or_, desc, asc, text, exists
from sqlalchemy.orm import joinedload, selectinload, subqueryload

from saint_datamodel import db_session
from saint_datamodel.models import (
    DetectionRule, RuleSource, MitreTechnique, MitreTactic, CveEntry,
    RuleMitreMapping, RuleCveMapping
)
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)

def validate_search_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and normalize search parameters"""
    return {
        'query': params.get('query', ''),
        'rule_types': params.get('rule_types', []),
        'severities': params.get('severities', []),
        'rule_sources': params.get('rule_sources', []),
        'tags': params.get('tags', []),
        'rule_platforms': params.get('rule_platforms', []),
        'mitre_techniques': params.get('mitre_techniques', []),
        'cve_ids': params.get('cve_ids', []),
        'is_active': params.get('is_active', True),
        'has_mitre': params.get('has_mitre'),
        'has_cves': params.get('has_cves'),
        'siem_platforms': params.get('siem_platforms', []),
        'aors': params.get('aors', []),
        'data_sources': params.get('data_sources', []),
        'info_controls': params.get('info_controls', []),
        'offset': int(params.get('offset', 0)),
        'limit': min(int(params.get('limit', 25)), 100),
        'sort_by': params.get('sort_by', 'modified_date'),
        'sort_dir': params.get('sort_dir', 'desc')
    }


def apply_search_filters(query, params: Dict[str, Any]):
    """Apply search filters to query with corrected JSONB operations"""
    
    # Text search
    if params['query']:
        search_term = f'%{params['query']}%'
        search_conditions = [
            DetectionRule.name.ilike(search_term),
            DetectionRule.description.ilike(search_term),
            DetectionRule.rule_id.ilike(search_term),
            DetectionRule.rule_content.ilike(search_term),
            RuleSource.name.ilike(search_term)
        ]
        
        # Add JSONB search for MITRE techniques if query looks like technique ID
        if params['query'].upper().startswith('T'):
            search_conditions.append(
                text("rule_metadata->'extracted_mitre_techniques' ? :tech_id").params(
                    tech_id=params['query'].upper()
                )
            )
        
        # Add JSONB search for CVE IDs if query looks like CVE
        if params['query'].upper().startswith('CVE'):
            search_conditions.append(
                text("rule_metadata->'extracted_cve_ids' ? :cve_id").params(
                    cve_id=params['query'].upper()
                )
            )
        
        query = query.join(RuleSource).filter(or_(*search_conditions))
    
    # Rule type filtering
    if params['rule_types']:
        query = query.filter(DetectionRule.rule_type.in_(params['rule_types']))
    
    # Severity filtering
    if params['severities']:
        query = query.filter(DetectionRule.severity.in_(params['severities']))
    
    # Rule source filtering
    if params['rule_sources']:
        source_ids = [int(s) for s in params['rule_sources'] if s.isdigit()]
        if source_ids:
            query = query.filter(DetectionRule.source_id.in_(source_ids))
    
    # Tags filtering
    if params['tags']:
        for tag in params['tags']:
            query = query.filter(DetectionRule.tags.contains([tag]))
    
    # Active status filtering
    if params['is_active'] is not None:
        query = query.filter(DetectionRule.is_active == params['is_active'])
    
    # Platform filtering from metadata
    if params['rule_platforms']:
        platform_conditions = []
        for platform in params['rule_platforms']:
            platform_conditions.append(
                text("rule_metadata->'rule_platforms' ? :platform").params(platform=platform)
            )
        if platform_conditions:
            query = query.filter(or_(*platform_conditions))
    
    # MITRE technique filtering - FIXED
    if params['mitre_techniques']:
        # Subquery for rules mapped via rule_mitre_mappings table
        technique_subquery = (
            query.session.query(RuleMitreMapping.rule_id)
            .join(MitreTechnique)
            .filter(MitreTechnique.technique_id.in_(params['mitre_techniques']))
            .subquery()
        )
        
        # Check metadata for each technique using ? operator
        metadata_conditions = []
        for tech_id in params['mitre_techniques']:
            metadata_conditions.append(
                text("rule_metadata->'extracted_mitre_techniques' ? :tech_id").params(tech_id=tech_id)
            )
        
        if metadata_conditions:
            query = query.filter(
                or_(
                    DetectionRule.id.in_(technique_subquery),
                    or_(*metadata_conditions)
                )
            )
        else:
            query = query.filter(DetectionRule.id.in_(technique_subquery))
    
    # CVE filtering - FIXED
    if params['cve_ids']:
        # Subquery for rules mapped via rule_cve_mappings table
        cve_subquery = (
            query.session.query(RuleCveMapping.rule_id)
            .join(CveEntry)
            .filter(CveEntry.cve_id.in_(params['cve_ids']))
            .subquery()
        )
        
        # Check metadata for each CVE using ? operator
        metadata_conditions = []
        for cve_id in params['cve_ids']:
            metadata_conditions.append(
                text("rule_metadata->'extracted_cve_ids' ? :cve_id").params(cve_id=cve_id)
            )
        
        if metadata_conditions:
            query = query.filter(
                or_(
                    DetectionRule.id.in_(cve_subquery),
                    or_(*metadata_conditions)
                )
            )
        else:
            query = query.filter(DetectionRule.id.in_(cve_subquery))
    
    # SIEM platform filtering
    if params['siem_platforms']:
        query = query.filter(
            DetectionRule.rule_metadata['siem_platform'].astext.in_(params['siem_platforms'])
        )
    
    # AOR filtering
    if params['aors']:
        query = query.filter(
            DetectionRule.rule_metadata['aor'].astext.in_(params['aors'])
        )
    
    # Data sources filtering
    if params['data_sources']:
        ds_conditions = []
        for ds in params['data_sources']:
            ds_conditions.append(
                text("rule_metadata->'data_sources' ? :ds").params(ds=ds)
            )
        if ds_conditions:
            query = query.filter(or_(*ds_conditions))
    
    # Info controls filtering
    if params['info_controls']:
        query = query.filter(
            DetectionRule.rule_metadata['info_controls'].astext.in_(params['info_controls'])
        )
    
    # Boolean filters for has_mitre
    if params['has_mitre'] is not None:
        if params['has_mitre']:
            query = query.filter(
                or_(
                    exists().where(RuleMitreMapping.rule_id == DetectionRule.id),
                    text("jsonb_array_length(rule_metadata->'extracted_mitre_techniques') > 0")
                )
            )
        else:
            query = query.filter(
                and_(
                    ~exists().where(RuleMitreMapping.rule_id == DetectionRule.id),
                    or_(
                        text("jsonb_array_length(rule_metadata->'extracted_mitre_techniques') = 0"),
                        text("rule_metadata->'extracted_mitre_techniques' IS NULL")
                    )
                )
            )
    
    # Boolean filters for has_cves
    if params['has_cves'] is not None:
        if params['has_cves']:
            query = query.filter(
                or_(
                    exists().where(RuleCveMapping.rule_id == DetectionRule.id),
                    text("jsonb_array_length(rule_metadata->'extracted_cve_ids') > 0")
                )
            )
        else:
            query = query.filter(
                and_(
                    ~exists().where(RuleCveMapping.rule_id == DetectionRule.id),
                    or_(
                        text("jsonb_array_length(rule_metadata->'extracted_cve_ids') = 0"),
                        text("rule_metadata->'extracted_cve_ids' IS NULL")
                    )
                )
            )
    
    return query

def apply_sorting(query, params: Dict[str, Any]):
    """Apply sorting to query"""
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
    """Calculate rule enrichment score"""
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
    
    # Metadata completeness (10%)
    if rule.rule_metadata:
        metadata = rule.rule_metadata
        if metadata.get('data_sources') and metadata.get('aor'):
            score += 5
        if metadata.get('info_controls') or metadata.get('hunt_id'):
            score += 5
    
    return min(score, 100.0)

def serialize_rule_summary(rule, mitre_technique_ids, cve_ids):
    """Serialize rule for list view"""
    platforms = []
    if rule.rule_metadata:
        platforms = rule.rule_metadata.get('rule_platforms', [])
    
    return {
        'id': str(rule.id),
        'source_rule_id': rule.rule_id,
        'title': rule.name,
        'description': rule.description[:500] + '...' if rule.description and len(rule.description) > 500 else rule.description,
        'rule_type': rule.rule_type,
        'severity': rule.severity or 'unknown',
        'status': 'active' if rule.is_active else 'inactive',
        'tags': rule.tags or [],
        'platforms': platforms,
        'rule_platforms': platforms,
        'created_date': rule.created_date.isoformat() if rule.created_date else None,
        'modified_date': rule.updated_date.isoformat() if rule.updated_date else None,
        'rule_source': rule.source.name if rule.source else rule.rule_type or '',
        'has_mitre_mapping': len(mitre_technique_ids) > 0,
        'has_cve_references': len(cve_ids) > 0,
        'enrichment_score': calculate_enrichment_score(rule, len(mitre_technique_ids), len(cve_ids)),
        'linked_technique_ids': mitre_technique_ids,
        'extracted_mitre_count': len(mitre_technique_ids),
        'extracted_cve_count': len(cve_ids)
    }

# api-handler/endpoints/rules_fixed.py
"""
Fixed rule details serialization for CrowdStrike and other edge cases
"""

def serialize_rule_detail(rule, mitre_techniques, cve_references):
    """Serialize rule with full metadata for detail view - handles edge cases"""
    platforms = []
    metadata = rule.rule_metadata or {}
    
    if metadata:
        platforms = metadata.get('rule_platforms', [])
    
    # Safely handle source relationship
    try:
        rule_source_name = rule.source.name if rule.source else 'Unknown'
    except Exception:
        # Handle broken foreign key or missing source
        rule_source_name = metadata.get('source_org') or rule.rule_type or 'Unknown'
    
    # Base rule data with safe field access
    rule_data = {
        'id': str(rule.id),
        'source_rule_id': rule.rule_id,
        'title': rule.name,
        'description': rule.description or '',
        'rule_type': rule.rule_type,
        'severity': rule.severity or 'medium',
        'status': 'active' if rule.is_active else 'inactive',
        'tags': rule.tags or [],
        'platforms': platforms,
        'rule_platforms': platforms,
        'created_date': rule.created_date.isoformat() if rule.created_date else None,
        'modified_date': rule.updated_date.isoformat() if rule.updated_date else None,
        'rule_source': rule_source_name,
        'has_mitre_mapping': len(mitre_techniques) > 0,
        'has_cve_references': len(cve_references) > 0,
        'enrichment_score': calculate_enrichment_score(rule, len(mitre_techniques), len(cve_references)),
        'linked_technique_ids': [t.get('technique_id') for t in mitre_techniques if t.get('technique_id')],
        'linked_techniques': mitre_techniques,
    }
    
    # Extended metadata fields with safe access
    rule_data['author'] = metadata.get('author')
    rule_data['source_file_path'] = rule.source_file_path if hasattr(rule, 'source_file_path') else None
    rule_data['raw_rule'] = None  # Don't expose raw rule content by default
    rule_data['rule_content'] = rule.rule_content if rule.rule_content else None
    rule_data['rule_metadata'] = metadata
    
    # Platform-specific details with safe access
    rule_data['elastic_details'] = rule.elastic_details if hasattr(rule, 'elastic_details') else None
    rule_data['sentinel_details'] = rule.sentinel_details if hasattr(rule, 'sentinel_details') else None
    rule_data['trinitycyber_details'] = rule.trinity_cyber_details if hasattr(rule, 'trinity_cyber_details') else None
    
    # Enrichment data
    rule_data['mitre_techniques'] = mitre_techniques
    rule_data['cve_references'] = cve_references
    rule_data['related_rules'] = []
    
    # New metadata fields from enhanced processors
    rule_data['siem_platform'] = metadata.get('siem_platform')
    rule_data['aor'] = metadata.get('aor')
    rule_data['source_org'] = metadata.get('source_org')
    rule_data['data_sources'] = metadata.get('data_sources', [])
    rule_data['info_controls'] = metadata.get('info_controls')
    rule_data['modified_by'] = metadata.get('modified_by')
    rule_data['hunt_id'] = metadata.get('hunt_id')
    rule_data['malware_family'] = metadata.get('malware_family')
    rule_data['intrusion_set'] = metadata.get('intrusion_set')
    rule_data['cwe_ids'] = metadata.get('cwe_ids', [])
    rule_data['validation'] = metadata.get('validation', {})
    
    return rule_data


def search_rules(params: Dict[str, Any]) -> Dict[str, Any]:
    """Search and filter rules"""
    try:
        search_params = validate_search_params(params)
        
        with db_session() as session:
            query = session.query(DetectionRule).options(
                joinedload(DetectionRule.source),
                selectinload(DetectionRule.mitre_mappings).joinedload(RuleMitreMapping.technique),
                selectinload(DetectionRule.cve_mappings).joinedload(RuleCveMapping.cve)
            ).distinct()
            
            query = apply_search_filters(query, search_params)
            total_count = query.count()
            
            query = apply_sorting(query, search_params)
            query = query.offset(search_params['offset']).limit(search_params['limit'])
            rules = query.all()
            
            serialized_rules = []
            for rule in rules:
                try:
                    mitre_technique_ids = [m.technique.technique_id for m in rule.mitre_mappings if m.technique]
                    cve_ids = [m.cve.cve_id for m in rule.cve_mappings if m.cve]
                    
                    rule_data = serialize_rule_summary(rule, mitre_technique_ids, cve_ids)
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
        return create_error_response(500, "Failed to search rules")

def get_rule_details(rule_id: str) -> Dict[str, Any]:
    """Get detailed rule information with better error handling"""
    try:
        # Try parsing as integer ID first
        try:
            db_id = int(rule_id)
            id_filter = DetectionRule.id == db_id
        except ValueError:
            # Fall back to string rule_id
            id_filter = DetectionRule.rule_id == rule_id
        
        with db_session() as session:
            # Use left outer joins to handle missing relationships
            rule = session.query(DetectionRule).options(
                selectinload(DetectionRule.source),  # Load source separately
                selectinload(DetectionRule.mitre_mappings).selectinload(RuleMitreMapping.technique),
                selectinload(DetectionRule.cve_mappings).selectinload(RuleCveMapping.cve)
            ).filter(id_filter).first()
            
            if not rule:
                return create_error_response(404, f"Rule not found: {rule_id}")
            
            # Build MITRE techniques list with safe access
            mitre_techniques = []
            if rule.mitre_mappings:
                for mapping in rule.mitre_mappings:
                    try:
                        if mapping.technique:
                            mitre_techniques.append({
                                'technique_id': mapping.technique.technique_id,
                                'name': mapping.technique.name,
                                'description': mapping.technique.description[:500] if mapping.technique.description else '',
                                'confidence': float(mapping.mapping_confidence) if mapping.mapping_confidence else 1.0
                            })
                    except Exception as e:
                        logger.warning(f"Error processing MITRE mapping for rule {rule_id}: {e}")
            
            # Build CVE references list with safe access
            cve_references = []
            if rule.cve_mappings:
                for mapping in rule.cve_mappings:
                    try:
                        if mapping.cve:
                            cve_references.append({
                                'cve_id': mapping.cve.cve_id,
                                'description': mapping.cve.description[:500] if mapping.cve.description else '',
                                'severity': mapping.cve.severity,
                                'cvss_v3_score': float(mapping.cve.cvss_v3_score) if mapping.cve.cvss_v3_score else None,
                                'published_date': mapping.cve.published_date.isoformat() if mapping.cve.published_date else None
                            })
                    except Exception as e:
                        logger.warning(f"Error processing CVE mapping for rule {rule_id}: {e}")
            
            # Serialize with enhanced error handling
            try:
                response_data = serialize_rule_detail(rule, mitre_techniques, cve_references)
                return create_api_response(200, response_data)
            except Exception as e:
                logger.error(f"Error serializing rule {rule_id}: {e}", exc_info=True)
                # Return minimal safe response
                return create_api_response(200, {
                    'id': str(rule.id),
                    'source_rule_id': rule.rule_id,
                    'title': rule.name or 'Unknown',
                    'description': rule.description or '',
                    'rule_type': rule.rule_type or 'unknown',
                    'severity': rule.severity or 'medium',
                    'status': 'active' if rule.is_active else 'inactive',
                    'error_note': 'Some rule details could not be loaded'
                })
            
    except Exception as e:
        logger.error(f"Error getting rule details for {rule_id}: {e}", exc_info=True)
        return create_error_response(500, f"Failed to get rule details: {str(e)}")

def get_filter_options(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get available filter options with counts"""
    try:
        with db_session() as session:
            options = {}
            
            # Rule sources
            source_query = session.query(
                RuleSource.id,
                RuleSource.name,
                RuleSource.source_type,
                func.count(DetectionRule.id).label('rule_count')
            ).join(DetectionRule).group_by(RuleSource.id).all()
            
            options['rule_sources'] = [
                {
                    'value': str(source.id),
                    'label': f"{source.name} ({source.rule_count})",
                    'source_type': source.source_type,
                    'rule_count': source.rule_count
                }
                for source in source_query
            ]
            
            # Rule types
            type_query = session.query(
                DetectionRule.rule_type,
                func.count(DetectionRule.id).label('count')
            ).filter(
                DetectionRule.rule_type.isnot(None)
            ).group_by(DetectionRule.rule_type).all()
            
            options['rule_types'] = [
                {
                    'value': rule_type,
                    'label': f"{rule_type.upper()} ({count})",
                    'count': count
                }
                for rule_type, count in type_query
            ]
            
            # Severities
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            severity_query = session.query(
                DetectionRule.severity,
                func.count(DetectionRule.id).label('count')
            ).filter(
                DetectionRule.severity.isnot(None)
            ).group_by(DetectionRule.severity).all()
            
            options['severities'] = sorted([
                {
                    'value': severity,
                    'label': f"{severity.capitalize()} ({count})",
                    'count': count,
                    'order': severity_order.get(severity, 99)
                }
                for severity, count in severity_query
            ], key=lambda x: x['order'])
            
            # MITRE tactics with rule counts
            tactic_query = session.query(
                MitreTactic.name,
                MitreTactic.tactic_id,
                func.count(DetectionRule.id.distinct()).label('rule_count')
            ).join(
                MitreTechnique,
                MitreTactic.id == MitreTechnique.tactic_id
            ).join(
                RuleMitreMapping,
                MitreTechnique.id == RuleMitreMapping.technique_id
            ).join(
                DetectionRule,
                RuleMitreMapping.rule_id == DetectionRule.id
            ).filter(
                DetectionRule.is_active == True
            ).group_by(MitreTactic.id).all()
            
            options['tactics'] = [
                {
                    'value': tactic.name,
                    'label': f"{tactic.name} ({tactic.rule_count})",
                    'tactic_id': tactic.tactic_id,
                    'rule_count': tactic.rule_count
                }
                for tactic in tactic_query
            ]
            
            # Rule platforms from metadata
            platform_rules = session.query(DetectionRule.rule_metadata).filter(
                text("rule_metadata->'rule_platforms' IS NOT NULL")
            ).all()
            
            platform_counts = defaultdict(int)
            for row in platform_rules:
                if row.rule_metadata and 'rule_platforms' in row.rule_metadata:
                    platforms = row.rule_metadata.get('rule_platforms', [])
                    for platform in platforms:
                        platform_counts[platform] += 1
            
            options['rule_platforms'] = [
                {
                    'value': platform,
                    'label': f"{platform} ({count})",
                    'count': count
                }
                for platform, count in sorted(platform_counts.items())
            ]
            
            # SIEM platforms
            siem_query = session.query(
                func.jsonb_extract_path_text(DetectionRule.rule_metadata, 'siem_platform').label('siem'),
                func.count(DetectionRule.id)
            ).filter(
                DetectionRule.rule_metadata.isnot(None)
            ).group_by('siem').having(
                func.jsonb_extract_path_text(DetectionRule.rule_metadata, 'siem_platform').isnot(None)
            ).all()
            
            options['siem_platforms'] = [
                {'value': siem, 'label': f"{siem} ({count})", 'count': count}
                for siem, count in siem_query if siem
            ]
            
            # Areas of Responsibility
            aor_query = session.query(
                func.jsonb_extract_path_text(DetectionRule.rule_metadata, 'aor').label('aor'),
                func.count(DetectionRule.id)
            ).filter(
                DetectionRule.rule_metadata.isnot(None)
            ).group_by('aor').having(
                func.jsonb_extract_path_text(DetectionRule.rule_metadata, 'aor').isnot(None)
            ).all()
            
            options['areas_of_responsibility'] = [
                {'value': aor, 'label': f"{aor} ({count})", 'count': count}
                for aor, count in aor_query if aor
            ]
            
            # Data sources
            data_sources = set()
            data_source_counts = defaultdict(int)
            
            rules_with_sources = session.query(DetectionRule.rule_metadata).filter(
                text("rule_metadata->'data_sources' IS NOT NULL")
            ).all()
            
            for row in rules_with_sources:
                if row.rule_metadata and 'data_sources' in row.rule_metadata:
                    sources = row.rule_metadata.get('data_sources', [])
                    for source in sources:
                        data_sources.add(source)
                        data_source_counts[source] += 1
            
            options['data_sources'] = [
                {'value': ds, 'label': f"{ds} ({data_source_counts[ds]})", 'count': data_source_counts[ds]}
                for ds in sorted(data_sources)
            ]
            
            # Information controls
            controls_query = session.query(
                func.jsonb_extract_path_text(DetectionRule.rule_metadata, 'info_controls').label('control'),
                func.count(DetectionRule.id)
            ).filter(
                DetectionRule.rule_metadata.isnot(None)
            ).group_by('control').having(
                func.jsonb_extract_path_text(DetectionRule.rule_metadata, 'info_controls').isnot(None)
            ).all()
            
            options['info_controls'] = [
                {'value': control, 'label': f"{control} ({count})", 'count': count}
                for control, count in controls_query if control
            ]
            
            return create_api_response(200, options)
            
    except Exception as e:
        logger.error(f"Error getting filter options: {e}", exc_info=True)
        return create_error_response(500, "Failed to get filter options")

def update_rule(rule_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    """Update rule metadata and properties"""
    try:
        with db_session() as session:
            rule = session.query(DetectionRule).filter_by(rule_id=rule_id).first()
            
            if not rule:
                return create_error_response(404, f"Rule not found: {rule_id}")
            
            # Update basic fields
            if 'name' in updates:
                rule.name = updates['name']
            if 'description' in updates:
                rule.description = updates['description']
            if 'severity' in updates:
                rule.severity = updates['severity']
            if 'is_active' in updates:
                rule.is_active = updates['is_active']
            
            # Update metadata
            if 'metadata_updates' in updates:
                if not rule.rule_metadata:
                    rule.rule_metadata = {}
                
                for key, value in updates['metadata_updates'].items():
                    rule.rule_metadata[key] = value
                
                # Mark metadata as modified for SQLAlchemy
                from sqlalchemy.orm.attributes import flag_modified
                flag_modified(rule, "rule_metadata")
            
            rule.updated_date = datetime.utcnow()
            session.commit()
            
            return create_api_response(200, {"message": "Rule updated successfully", "rule_id": rule_id})
            
    except Exception as e:
        logger.error(f"Error updating rule {rule_id}: {e}", exc_info=True)
        return create_error_response(500, "Failed to update rule")