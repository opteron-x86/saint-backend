# endpoints/cve.py
"""
Enhanced endpoint handlers for CVE data.
Works with improved CVE processing and extraction.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_, desc, asc, text
from sqlalchemy.orm import joinedload

from saint_datamodel import db_session
from saint_datamodel.models import CveEntry, DetectionRule, RuleCveMapping, RuleSource
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)

def validate_cve_search_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and sanitize CVE search parameters"""
    validated = {}
    
    # Text search
    validated['query'] = params.get('query', '').strip()[:100] if params.get('query') else None
    
    # Pagination
    validated['offset'] = max(0, params.get('offset', 0))
    validated['limit'] = min(max(1, params.get('limit', 100)), 500)
    
    # Sorting
    valid_sort_fields = ['cve_id', 'published_date', 'modified_date', 'cvss_v3_score', 'severity']
    validated['sort_by'] = params.get('sort_by') if params.get('sort_by') in valid_sort_fields else 'published_date'
    validated['sort_dir'] = 'desc' if params.get('sort_dir') == 'desc' else 'asc'
    
    # Severity filter
    valid_severities = ['low', 'medium', 'high', 'critical']
    severities = params.get('severities', [])
    if isinstance(severities, str):
        severities = [severities]
    validated['severities'] = [s.lower() for s in severities if s.lower() in valid_severities]
    
    # CVSS score range
    try:
        validated['min_cvss'] = float(params.get('min_cvss', 0)) if params.get('min_cvss') else None
        validated['max_cvss'] = float(params.get('max_cvss', 10)) if params.get('max_cvss') else None
    except (ValueError, TypeError):
        validated['min_cvss'] = None
        validated['max_cvss'] = None
    
    # Date range
    validated['days_back'] = None
    if params.get('days_back'):
        try:
            validated['days_back'] = max(1, int(params.get('days_back')))
        except (ValueError, TypeError):
            pass
    
    # Filter options
    validated['with_rules_only'] = str(params.get('with_rules_only', 'false')).lower() == 'true'
    
    return validated

def get_cve_details(cve_id: str) -> Dict[str, Any]:
    """
    Get detailed CVE information with associated rules.
    """
    try:
        # Validate CVE ID format
        if not cve_id.upper().startswith('CVE-'):
            return create_error_response(400, "Invalid CVE ID format")
        
        cve_id = cve_id.upper()
        
        with db_session() as session:
            # Get CVE with basic info
            cve = session.query(CveEntry).filter_by(cve_id=cve_id).first()
            
            if not cve:
                return create_error_response(404, f"CVE not found: {cve_id}")
            
            # Get associated rules via mappings
            mapped_rules = (
                session.query(DetectionRule)
                .join(RuleCveMapping)
                .filter(RuleCveMapping.cve_id == cve.id)
                .filter(DetectionRule.is_active == True)
                .options(joinedload(DetectionRule.source))
                .all()
            )
            
            # Get rules that reference this CVE in metadata
            metadata_rules = (
                session.query(DetectionRule)
                .filter(
                    text("rule_metadata->'extracted_cve_ids' ? :cve_id")
                )
                .filter(DetectionRule.is_active == True)
                .options(joinedload(DetectionRule.source))
                .params(cve_id=cve_id)
                .all()
            )
            
            # Combine and deduplicate rules
            all_rules = {rule.id: rule for rule in mapped_rules + metadata_rules}
            
            # Build response
            cve_data = {
                'id': cve.id,
                'cve_id': cve.cve_id,
                'description': cve.description,
                'published_date': cve.published_date.isoformat() if cve.published_date else None,
                'modified_date': cve.modified_date.isoformat() if cve.modified_date else None,
                'cvss_v3_score': float(cve.cvss_v3_score) if cve.cvss_v3_score else None,
                'cvss_v3_vector': cve.cvss_v3_vector,
                'cvss_v2_score': float(cve.cvss_v2_score) if cve.cvss_v2_score else None,
                'cvss_v2_vector': cve.cvss_v2_vector,
                'severity': cve.severity,
                'cwe_ids': cve.cwe_ids or [],
                'affected_products': cve.affected_products or {},
                'cve_references': cve.cve_references or {},
                'exploitability_score': float(cve.exploitability_score) if cve.exploitability_score else None,
                'impact_score': float(cve.impact_score) if cve.impact_score else None,
                'associated_rules': [
                    {
                        'id': rule.id,
                        'rule_id': rule.rule_id,
                        'name': rule.name,
                        'severity': rule.severity,
                        'rule_type': rule.rule_type,
                        'source': rule.source.name if rule.source else 'Unknown',
                        'is_active': rule.is_active
                    }
                    for rule in all_rules.values()
                ],
                'rule_count': len(all_rules),
                'created_date': cve.created_date.isoformat() if cve.created_date else None,
                'updated_date': cve.updated_date.isoformat() if cve.updated_date else None
            }
            
            return create_api_response(200, cve_data)

    except Exception as e:
        logger.error(f"Error getting CVE details for {cve_id}: {e}", exc_info=True)
        return create_error_response(500, "Failed to retrieve CVE details")

def search_cves(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Search CVEs with enhanced filtering and rule association information.
    """
    try:
        # Validate search parameters
        search_params = validate_cve_search_params(params)
        
        with db_session() as session:
            # Build base query
            query = session.query(CveEntry)
            
            # Text search
            if search_params['query']:
                search_term = f"%{search_params['query']}%"
                query = query.filter(
                    or_(
                        CveEntry.cve_id.ilike(search_term),
                        CveEntry.description.ilike(search_term)
                    )
                )
            
            # Severity filter
            if search_params['severities']:
                query = query.filter(CveEntry.severity.in_(search_params['severities']))
            
            # CVSS score range
            if search_params['min_cvss'] is not None:
                query = query.filter(CveEntry.cvss_v3_score >= search_params['min_cvss'])
            if search_params['max_cvss'] is not None:
                query = query.filter(CveEntry.cvss_v3_score <= search_params['max_cvss'])
            
            # Date range filter
            if search_params['days_back']:
                cutoff_date = datetime.utcnow() - timedelta(days=search_params['days_back'])
                query = query.filter(CveEntry.published_date >= cutoff_date)
            
            # Filter to only CVEs with associated rules
            if search_params['with_rules_only']:
                # Subquery for CVEs with rule mappings
                mapped_cve_ids = (
                    session.query(RuleCveMapping.cve_id)
                    .distinct()
                    .subquery()
                )
                
                # Subquery for CVEs referenced in rule metadata
                metadata_cve_query = (
                    session.query(CveEntry.id)
                    .join(
                        DetectionRule,
                        text("rule_metadata->'extracted_cve_ids' ? cve_entries.cve_id")
                    )
                    .distinct()
                    .subquery()
                )
                
                query = query.filter(
                    or_(
                        CveEntry.id.in_(mapped_cve_ids),
                        CveEntry.id.in_(metadata_cve_query)
                    )
                )
            
            # Get total count before pagination
            total_count = query.count()
            
            # Apply sorting
            sort_column = getattr(CveEntry, search_params['sort_by'], CveEntry.published_date)
            if search_params['sort_dir'] == 'desc':
                query = query.order_by(desc(sort_column))
            else:
                query = query.order_by(asc(sort_column))
            
            # Apply pagination
            cves = query.offset(search_params['offset']).limit(search_params['limit']).all()
            
            # Serialize CVEs with rule count information
            cve_list = []
            for cve in cves:
                # Get rule count for this CVE (both mappings and metadata)
                mapped_rule_count = (
                    session.query(func.count(DetectionRule.id.distinct()))
                    .join(RuleCveMapping)
                    .filter(RuleCveMapping.cve_id == cve.id)
                    .filter(DetectionRule.is_active == True)
                    .scalar()
                )
                
                metadata_rule_count = (
                    session.query(func.count(DetectionRule.id))
                    .filter(
                        text("rule_metadata->'extracted_cve_ids' ? :cve_id")
                    )
                    .filter(DetectionRule.is_active == True)
                    .params(cve_id=cve.cve_id)
                    .scalar()
                )
                
                total_rule_count = max(mapped_rule_count, metadata_rule_count)  # May have overlap
                
                cve_data = {
                    'id': cve.id,
                    'cve_id': cve.cve_id,
                    'description': cve.description[:500] + '...' if cve.description and len(cve.description) > 500 else cve.description,
                    'published_date': cve.published_date.isoformat() if cve.published_date else None,
                    'modified_date': cve.modified_date.isoformat() if cve.modified_date else None,
                    'cvss_v3_score': float(cve.cvss_v3_score) if cve.cvss_v3_score else None,
                    'severity': cve.severity,
                    'rule_count': total_rule_count,
                    'cwe_ids': cve.cwe_ids or []
                }
                cve_list.append(cve_data)
            
            response_data = {
                'items': cve_list,
                'total': total_count,
                'offset': search_params['offset'],
                'limit': search_params['limit'],
                'has_more': (search_params['offset'] + search_params['limit']) < total_count,
                'search_params': search_params
            }
            
            return create_api_response(200, response_data)

    except Exception as e:
        logger.error(f"Error searching CVEs: {e}", exc_info=True)
        return create_error_response(500, "CVE search failed")

def get_cve_stats() -> Dict[str, Any]:
    """Get statistics about CVE data and coverage"""
    try:
        with db_session() as session:
            # Total CVEs
            total_cves = session.query(func.count(CveEntry.id)).scalar()
            
            # CVEs by severity
            severity_stats = (
                session.query(
                    CveEntry.severity,
                    func.count(CveEntry.id)
                )
                .filter(CveEntry.severity.isnot(None))
                .group_by(CveEntry.severity)
                .all()
            )
            
            # CVEs with rule mappings
            cves_with_mappings = (
                session.query(func.count(CveEntry.id.distinct()))
                .join(RuleCveMapping)
                .scalar()
            )
            
            # CVEs referenced in rule metadata
            cves_in_metadata = (
                session.query(func.count(CveEntry.id.distinct()))
                .join(
                    DetectionRule,
                    text("rule_metadata->'extracted_cve_ids' ? cve_entries.cve_id")
                )
                .scalar()
            )
            
            # Recent CVEs (last 30 days)
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            recent_cves = (
                session.query(func.count(CveEntry.id))
                .filter(CveEntry.published_date >= thirty_days_ago)
                .scalar()
            )
            
            # High severity CVEs (CVSS >= 7.0)
            high_severity_cves = (
                session.query(func.count(CveEntry.id))
                .filter(CveEntry.cvss_v3_score >= 7.0)
                .scalar()
            )
            
            # Critical CVEs (CVSS >= 9.0)
            critical_cves = (
                session.query(func.count(CveEntry.id))
                .filter(CveEntry.cvss_v3_score >= 9.0)
                .scalar()
            )
            
            stats = {
                'total_cves': total_cves,
                'coverage': {
                    'with_rule_mappings': cves_with_mappings,
                    'referenced_in_metadata': cves_in_metadata,
                    'coverage_percentage': round((cves_with_mappings / total_cves * 100), 2) if total_cves > 0 else 0
                },
                'by_severity': {stat[0]: stat[1] for stat in severity_stats},
                'risk_metrics': {
                    'recent_cves_30_days': recent_cves,
                    'high_severity_count': high_severity_cves,
                    'critical_severity_count': critical_cves
                },
                'summary': {
                    'coverage_status': 'good' if (cves_with_mappings / total_cves > 0.1) else 'needs_improvement' if total_cves > 0 else 'no_data',
                    'recent_activity': 'high' if recent_cves > 50 else 'medium' if recent_cves > 10 else 'low'
                }
            }
            
            return create_api_response(200, stats)

    except Exception as e:
        logger.error(f"Error getting CVE stats: {e}", exc_info=True)
        return create_error_response(500, "Failed to get CVE statistics")

def get_trending_cves(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get trending CVEs based on recent activity and severity"""
    try:
        days_back = min(max(1, params.get('days_back', 7)), 90)
        limit = min(max(1, params.get('limit', 20)), 100)
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)
        
        with db_session() as session:
            # Get recent high-severity CVEs
            trending_query = (
                session.query(CveEntry)
                .filter(CveEntry.published_date >= cutoff_date)
                .filter(CveEntry.cvss_v3_score >= 6.0)  # Medium to critical
                .order_by(desc(CveEntry.cvss_v3_score), desc(CveEntry.published_date))
                .limit(limit)
            )
            
            trending_cves = trending_query.all()
            
            # Add rule association information
            trending_list = []
            for cve in trending_cves:
                # Get associated rule count
                rule_count = (
                    session.query(func.count(DetectionRule.id.distinct()))
                    .outerjoin(RuleCveMapping, RuleCveMapping.cve_id == cve.id)
                    .outerjoin(
                        DetectionRule,
                        or_(
                            DetectionRule.id == RuleCveMapping.rule_id,
                            text("rule_metadata->'extracted_cve_ids' ? :cve_id")
                        )
                    )
                    .filter(DetectionRule.is_active == True)
                    .params(cve_id=cve.cve_id)
                    .scalar()
                )
                
                cve_data = {
                    'cve_id': cve.cve_id,
                    'description': cve.description[:300] + '...' if cve.description and len(cve.description) > 300 else cve.description,
                    'published_date': cve.published_date.isoformat() if cve.published_date else None,
                    'cvss_v3_score': float(cve.cvss_v3_score) if cve.cvss_v3_score else None,
                    'severity': cve.severity,
                    'rule_count': rule_count or 0,
                    'coverage_status': 'covered' if rule_count > 0 else 'not_covered'
                }
                trending_list.append(cve_data)
            
            return create_api_response(200, {
                'trending_cves': trending_list,
                'period_days': days_back,
                'total_found': len(trending_list),
                'coverage_summary': {
                    'covered': len([c for c in trending_list if c['coverage_status'] == 'covered']),
                    'not_covered': len([c for c in trending_list if c['coverage_status'] == 'not_covered'])
                }
            })

    except Exception as e:
        logger.error(f"Error getting trending CVEs: {e}", exc_info=True)
        return create_error_response(500, "Failed to get trending CVEs")