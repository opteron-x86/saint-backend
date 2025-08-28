# endpoints/mitre.py
"""
Endpoint handlers for MITRE ATT&CK data.
"""

import logging
from typing import Dict, Any, List, Optional
from sqlalchemy import func, and_, or_, text, desc
from sqlalchemy.orm import joinedload, selectinload

from saint_datamodel import db_session
from saint_datamodel.models import (
    MitreTactic, MitreTechnique, DetectionRule, 
    RuleMitreMapping, RuleSource
)
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)

def get_mitre_matrix(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get the full ATT&CK matrix data with tactics containing nested techniques.
    """
    try:
        with db_session() as session:
            # Get all tactics with their techniques loaded
            tactics_query = (
                session.query(MitreTactic)
                .options(
                    selectinload(MitreTactic.techniques)
                    .selectinload(MitreTechnique.subtechniques)
                )
                .order_by(MitreTactic.id)
            )
            
            tactics = tactics_query.all()
            
            # Process tactics and filter techniques
            matrix_data = []
            for tactic in tactics:
                # Only include top-level techniques (no parent)
                top_level_techniques = [
                    tech for tech in tactic.techniques 
                    if tech.parent_technique_id is None
                ]
                
                # Build technique data with subtechniques
                technique_data = []
                for technique in top_level_techniques:
                    tech_info = {
                        'id': technique.id,
                        'technique_id': technique.technique_id,
                        'name': technique.name,
                        'description': technique.description[:200] + '...' if technique.description and len(technique.description) > 200 else technique.description,
                        'platforms': technique.platforms or [],
                        'data_sources': technique.data_sources or [],
                        'subtechniques': []
                    }
                    
                    # Add subtechniques
                    for subtech in technique.subtechniques:
                        tech_info['subtechniques'].append({
                            'id': subtech.id,
                            'technique_id': subtech.technique_id,
                            'name': subtech.name,
                            'description': subtech.description[:200] + '...' if subtech.description and len(subtech.description) > 200 else subtech.description,
                            'platforms': subtech.platforms or []
                        })
                    
                    technique_data.append(tech_info)
                
                tactic_info = {
                    'id': tactic.id,
                    'tactic_id': tactic.tactic_id,
                    'name': tactic.name,
                    'description': tactic.description,
                    'techniques': technique_data
                }
                
                matrix_data.append(tactic_info)
            
            return create_api_response(200, {
                'matrix': matrix_data,
                'metadata': {
                    'total_tactics': len(matrix_data),
                    'total_techniques': sum(len(t['techniques']) for t in matrix_data),
                    'total_subtechniques': sum(
                        len(tech['subtechniques']) 
                        for tactic in matrix_data 
                        for tech in tactic['techniques']
                    )
                }
            })

    except Exception as e:
        logger.error(f"Error fetching MITRE matrix: {e}", exc_info=True)
        return create_error_response(500, "Failed to fetch MITRE matrix data")


def get_coverage_analysis(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get rule coverage analysis for MITRE techniques.
    """
    try:
        platforms = params.get('platforms', [])
        
        # Handle include_details parameter - might be a list from multiValueQueryStringParameters
        include_details_param = params.get('include_details', 'false')
        if isinstance(include_details_param, list):
            include_details_param = include_details_param[0] if include_details_param else 'false'
        include_details = str(include_details_param).lower() == 'true'
        
        # Add pagination support
        offset = params.get('offset', 0)
        limit = params.get('limit', 0)  # 0 means no limit
        
        with db_session() as session:
            # Base query for all techniques
            techniques_query = session.query(MitreTechnique)
            
            # Apply platform filter if provided
            if platforms:
                platform_condition = text("platforms && :platforms")
                techniques_query = techniques_query.filter(platform_condition).params(platforms=platforms)
            
            all_techniques = techniques_query.all()
            
            coverage_data = []
            total_techniques = len(all_techniques)
            covered_techniques = 0
            
            for technique in all_techniques:
                # Get rules via mappings
                mapped_rules = (
                    session.query(DetectionRule)
                    .join(RuleMitreMapping)
                    .filter(RuleMitreMapping.technique_id == technique.id)
                    .filter(DetectionRule.is_active == True)
                    .options(joinedload(DetectionRule.source))
                    .all()
                )
                
                # Get rules via metadata (extracted techniques)  
                metadata_rules = (
                    session.query(DetectionRule)
                    .filter(
                        text("rule_metadata->'extracted_mitre_techniques' ? :technique_id")
                    )
                    .filter(DetectionRule.is_active == True)
                    .options(joinedload(DetectionRule.source))
                    .params(technique_id=technique.technique_id)
                    .all()
                )
                
                # Combine and deduplicate rules
                all_rules = {rule.id: rule for rule in mapped_rules + metadata_rules}
                rule_count = len(all_rules)
                
                if rule_count > 0:
                    covered_techniques += 1
                
                # Build technique coverage data
                technique_data = {
                    'technique_id': technique.technique_id,
                    'name': technique.name,
                    'count': rule_count,
                    'coverage_level': get_coverage_level(rule_count),
                    'platforms': technique.platforms or []
                }
                
                # Add rule details if requested, but limit to 10 rules per technique
                if include_details and rule_count > 0:
                    rules_list = list(all_rules.values())[:10]  # Limit to 10 rules
                    technique_data['rules'] = [
                        {
                            'id': rule.id,
                            'title': rule.name,
                            'severity': rule.severity,
                            'source': rule.source.name if rule.source else 'Unknown'
                        }
                        for rule in rules_list
                    ]
                    # Indicate if there are more rules
                    if rule_count > 10:
                        technique_data['has_more_rules'] = True
                        technique_data['total_rules'] = rule_count
                else:
                    technique_data['rules'] = []
                
                coverage_data.append(technique_data)
            
            # Calculate coverage percentage
            coverage_percentage = (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0
            
            # Sort by coverage count (most covered first)
            coverage_data.sort(key=lambda x: x['count'], reverse=True)
            
            # Apply pagination if requested
            if limit > 0:
                paginated_data = coverage_data[offset:offset + limit]
            else:
                # Even without explicit pagination, limit to prevent huge responses
                # Return top 500 techniques to avoid response size issues
                paginated_data = coverage_data[:500]
            
            response_data = {
                'total_techniques': total_techniques,
                'covered_techniques': covered_techniques,
                'coverage_percentage': round(coverage_percentage, 2),
                'techniques': paginated_data,
                'coverage_levels': {
                    'none': len([t for t in coverage_data if t['coverage_level'] == 'none']),
                    'low': len([t for t in coverage_data if t['coverage_level'] == 'low']),
                    'medium': len([t for t in coverage_data if t['coverage_level'] == 'medium']),
                    'high': len([t for t in coverage_data if t['coverage_level'] == 'high'])
                }
            }
            
            # Add pagination metadata if applicable
            if limit > 0:
                response_data['pagination'] = {
                    'offset': offset,
                    'limit': limit,
                    'total': len(coverage_data),
                    'has_more': (offset + limit) < len(coverage_data)
                }
            
            return create_api_response(200, response_data)

    except Exception as e:
        logger.error(f"Error in coverage analysis: {e}", exc_info=True)
        return create_error_response(500, "Failed to generate coverage analysis")

def get_coverage_level(rule_count: int) -> str:
    """Determine coverage level based on rule count"""
    if rule_count == 0:
        return 'none'
    elif rule_count <= 2:
        return 'low'
    elif rule_count <= 5:
        return 'medium'
    else:
        return 'high'

def get_techniques_list(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get paginated list of MITRE techniques with search and filters"""
    try:
        # Parse parameters
        query = params.get('query', '').strip()
        platforms = params.get('platforms', [])
        tactics = params.get('tactics', [])
        offset = max(0, params.get('offset', 0))
        limit = min(max(1, params.get('limit', 100)), 500)
        
        with db_session() as session:
            # Build base query
            techniques_query = (
                session.query(MitreTechnique)
                .options(joinedload(MitreTechnique.tactic))
            )
            
            # Apply search filter
            if query:
                search_term = f"%{query}%"
                techniques_query = techniques_query.filter(
                    or_(
                        MitreTechnique.technique_id.ilike(search_term),
                        MitreTechnique.name.ilike(search_term),
                        MitreTechnique.description.ilike(search_term)
                    )
                )
            
            # Apply platform filter
            if platforms:
                platform_condition = text("platforms && :platforms")
                techniques_query = techniques_query.filter(platform_condition).params(platforms=platforms)
            
            # Apply tactic filter
            if tactics:
                techniques_query = (
                    techniques_query.join(MitreTactic)
                    .filter(MitreTactic.name.in_(tactics))
                )
            
            # Get total count
            total_count = techniques_query.count()
            
            # Apply pagination and ordering
            techniques = (
                techniques_query
                .order_by(MitreTechnique.technique_id)
                .offset(offset)
                .limit(limit)
                .all()
            )
            
            # Serialize techniques
            technique_list = []
            for technique in techniques:
                technique_data = {
                    'id': technique.id,
                    'technique_id': technique.technique_id,
                    'name': technique.name,
                    'description': technique.description[:300] + '...' if technique.description and len(technique.description) > 300 else technique.description,
                    'platforms': technique.platforms or [],
                    'data_sources': technique.data_sources or [],
                    'tactic': {
                        'id': technique.tactic.id,
                        'name': technique.tactic.name,
                        'tactic_id': technique.tactic.tactic_id
                    } if technique.tactic else None,
                    'is_subtechnique': technique.parent_technique_id is not None
                }
                technique_list.append(technique_data)
            
            return create_api_response(200, {
                'items': technique_list,
                'total': total_count,
                'offset': offset,
                'limit': limit,
                'has_more': (offset + limit) < total_count
            })

    except Exception as e:
        logger.error(f"Error getting techniques list: {e}", exc_info=True)
        return create_error_response(500, "Failed to get techniques list")

def get_tactics_list() -> Dict[str, Any]:
    """Get list of all MITRE tactics"""
    try:
        with db_session() as session:
            tactics = (
                session.query(MitreTactic)
                .order_by(MitreTactic.tactic_id)
                .all()
            )
            
            tactic_list = []
            for tactic in tactics:
                # Count techniques for this tactic
                technique_count = (
                    session.query(func.count(MitreTechnique.id))
                    .filter(MitreTechnique.tactic_id == tactic.id)
                    .scalar()
                )
                
                tactic_data = {
                    'id': tactic.id,
                    'tactic_id': tactic.tactic_id,
                    'name': tactic.name,
                    'description': tactic.description,
                    'technique_count': technique_count
                }
                tactic_list.append(tactic_data)
            
            return create_api_response(200, {
                'tactics': tactic_list,
                'total': len(tactic_list)
            })

    except Exception as e:
        logger.error(f"Error getting tactics list: {e}", exc_info=True)
        return create_error_response(500, "Failed to get tactics list")

def get_technique_details(technique_id: str) -> Dict[str, Any]:
    """Get detailed information about a specific MITRE technique"""
    try:
        with db_session() as session:
            technique = (
                session.query(MitreTechnique)
                .options(
                    joinedload(MitreTechnique.tactic),
                    joinedload(MitreTechnique.parent_technique),
                    selectinload(MitreTechnique.subtechniques)
                )
                .filter(MitreTechnique.technique_id == technique_id)
                .first()
            )
            
            if not technique:
                return create_error_response(404, f"MITRE technique not found: {technique_id}")
            
            # Get associated rules
            mapped_rules = (
                session.query(DetectionRule)
                .join(RuleMitreMapping)
                .filter(RuleMitreMapping.technique_id == technique.id)
                .filter(DetectionRule.is_active == True)
                .options(joinedload(DetectionRule.source))
                .all()
            )
            
            metadata_rules = (
                session.query(DetectionRule)
                .filter(
                    text("rule_metadata->'extracted_mitre_techniques' ? :technique_id")
                )
                .filter(DetectionRule.is_active == True)
                .options(joinedload(DetectionRule.source))
                .params(technique_id=technique_id)
                .all()
            )
            
            # Combine and deduplicate
            all_rules = {rule.id: rule for rule in mapped_rules + metadata_rules}
            
            technique_data = {
                'id': technique.id,
                'technique_id': technique.technique_id,
                'name': technique.name,
                'description': technique.description,
                'platforms': technique.platforms or [],
                'data_sources': technique.data_sources or [],
                'detection_description': technique.detection_description,
                'mitigation_description': technique.mitigation_description,
                'external_references': technique.external_references,
                'tactic': {
                    'id': technique.tactic.id,
                    'name': technique.tactic.name,
                    'tactic_id': technique.tactic.tactic_id
                } if technique.tactic else None,
                'parent_technique': {
                    'id': technique.parent_technique.id,
                    'technique_id': technique.parent_technique.technique_id,
                    'name': technique.parent_technique.name
                } if technique.parent_technique else None,
                'subtechniques': [
                    {
                        'id': subtech.id,
                        'technique_id': subtech.technique_id,
                        'name': subtech.name
                    }
                    for subtech in technique.subtechniques
                ],
                'associated_rules': [
                    {
                        'id': rule.id,
                        'rule_id': rule.rule_id,
                        'name': rule.name,
                        'severity': rule.severity,
                        'source': rule.source.name if rule.source else 'Unknown'
                    }
                    for rule in all_rules.values()
                ],
                'rule_count': len(all_rules)
            }
            
            return create_api_response(200, technique_data)

    except Exception as e:
        logger.error(f"Error getting technique details for {technique_id}: {e}", exc_info=True)
        return create_error_response(500, "Failed to get technique details")