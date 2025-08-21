# endpoints/filters.py
"""
Enhanced endpoint handler for retrieving filter options.
Provides comprehensive filter data for the frontend UI.
"""

import logging
from typing import Dict, Any, List, Set
from sqlalchemy import func, distinct, text
from collections import Counter

from saint_datamodel import db_session
from saint_datamodel.models import (
    RuleSource, DetectionRule, MitreTactic, MitreTechnique,
    CveEntry, RuleMitreMapping, RuleCveMapping
)
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)

def get_filter_options() -> Dict[str, Any]:
    """
    Get comprehensive filter options for building UI filter controls.
    Enhanced to work with improved data processing.
    """
    try:
        with db_session() as session:
            filter_options = {}
            
            # Rule Sources
            filter_options['rule_sources'] = get_rule_sources_filter(session)
            
            # Rule Types
            filter_options['rule_types'] = get_rule_types_filter(session)
            
            # Severities
            filter_options['severities'] = get_severities_filter(session)
            
            # MITRE Tactics
            filter_options['tactics'] = get_tactics_filter(session)
            
            # Platforms (from MITRE techniques)
            filter_options['platforms'] = get_platforms_filter(session)
            
            # Rule Platforms (from rule metadata)
            filter_options['rule_platforms'] = get_rule_platforms_filter(session)
            
            # Validation Statuses
            filter_options['validation_statuses'] = get_validation_statuses_filter(session)
            
            # Popular Tags
            filter_options['popular_tags'] = get_popular_tags_filter(session)
            
            # CVE Severities (for CVE filtering)
            filter_options['cve_severities'] = get_cve_severities_filter(session)
            
            # Date Ranges (predefined options)
            filter_options['date_ranges'] = get_date_ranges_filter()
            
            return create_api_response(200, filter_options)

    except Exception as e:
        logger.error(f"Error getting filter options: {e}", exc_info=True)
        return create_error_response(500, "Failed to get filter options")

def get_rule_sources_filter(session) -> List[Dict[str, Any]]:
    """Get active rule sources with rule counts"""
    try:
        sources_with_counts = (
            session.query(
                RuleSource.id,
                RuleSource.name,
                RuleSource.source_type,
                func.count(DetectionRule.id).label('rule_count')
            )
            .outerjoin(DetectionRule)
            .filter(RuleSource.is_active == True)
            .group_by(RuleSource.id, RuleSource.name, RuleSource.source_type)
            .order_by(RuleSource.name)
            .all()
        )
        
        return [
            {
                "value": str(source.id),
                "label": f"{source.name} ({source.rule_count})",
                "source_type": source.source_type,
                "rule_count": source.rule_count
            }
            for source in sources_with_counts
        ]
    except Exception as e:
        logger.error(f"Error getting rule sources filter: {e}")
        return []

def get_rule_types_filter(session) -> List[Dict[str, Any]]:
    """Get distinct rule types with counts"""
    try:
        rule_types = (
            session.query(
                DetectionRule.rule_type,
                func.count(DetectionRule.id).label('count')
            )
            .filter(DetectionRule.rule_type.isnot(None))
            .group_by(DetectionRule.rule_type)
            .order_by(DetectionRule.rule_type)
            .all()
        )
        
        return [
            {
                "value": rt.rule_type,
                "label": f"{rt.rule_type.upper()} ({rt.count})",
                "count": rt.count
            }
            for rt in rule_types
        ]
    except Exception as e:
        logger.error(f"Error getting rule types filter: {e}")
        return []

def get_severities_filter(session) -> List[Dict[str, Any]]:
    """Get distinct severities with counts"""
    try:
        severities = (
            session.query(
                DetectionRule.severity,
                func.count(DetectionRule.id).label('count')
            )
            .filter(DetectionRule.severity.isnot(None))
            .group_by(DetectionRule.severity)
            .order_by(DetectionRule.severity)
            .all()
        )
        
        # Define severity order for better UX
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        
        result = []
        for sev in severities:
            result.append({
                "value": sev.severity,
                "label": f"{sev.severity.capitalize()} ({sev.count})",
                "count": sev.count,
                "order": severity_order.get(sev.severity.lower(), 99)
            })
        
        # Sort by defined order
        result.sort(key=lambda x: x['order'])
        return result
    except Exception as e:
        logger.error(f"Error getting severities filter: {e}")
        return []

def get_tactics_filter(session) -> List[Dict[str, Any]]:
    """Get MITRE tactics with rule counts"""
    try:
        tactics_with_counts = (
            session.query(
                MitreTactic.tactic_id,
                MitreTactic.name,
                func.count(DetectionRule.id.distinct()).label('rule_count')
            )
            .outerjoin(MitreTechnique, MitreTactic.id == MitreTechnique.tactic_id)
            .outerjoin(RuleMitreMapping, MitreTechnique.id == RuleMitreMapping.technique_id)
            .outerjoin(DetectionRule, RuleMitreMapping.rule_id == DetectionRule.id)
            .group_by(MitreTactic.tactic_id, MitreTactic.name)
            .order_by(MitreTactic.name)
            .all()
        )
        
        return [
            {
                "value": tactic.name,
                "label": f"{tactic.name} ({tactic.rule_count})",
                "tactic_id": tactic.tactic_id,
                "rule_count": tactic.rule_count
            }
            for tactic in tactics_with_counts
        ]
    except Exception as e:
        logger.error(f"Error getting tactics filter: {e}")
        return []

def get_platforms_filter(session) -> List[Dict[str, Any]]:
    """Get distinct platforms from MITRE techniques"""
    try:
        # Get all platforms from MITRE techniques
        platforms_result = (
            session.query(MitreTechnique.platforms)
            .filter(MitreTechnique.platforms.isnot(None))
            .all()
        )
        
        # Flatten and count platforms
        platform_counter = Counter()
        for row in platforms_result:
            if row.platforms:
                for platform in row.platforms:
                    platform_counter[platform] += 1
        
        # Convert to sorted list
        platforms = [
            {
                "value": platform,
                "label": f"{platform} ({count})",
                "count": count
            }
            for platform, count in platform_counter.most_common()
        ]
        
        return platforms
    except Exception as e:
        logger.error(f"Error getting platforms filter: {e}")
        return []

def get_rule_platforms_filter(session) -> List[Dict[str, Any]]:
    """Get distinct rule platforms from rule metadata"""
    try:
        # Query rules that have rule_platforms in metadata
        rules_with_platforms = (
            session.query(DetectionRule.rule_metadata)
            .filter(text("rule_metadata ? 'rule_platforms'"))
            .filter(text("jsonb_array_length(rule_metadata->'rule_platforms') > 0"))
            .all()
        )
        
        # Extract and count platforms
        platform_counter = Counter()
        for row in rules_with_platforms:
            if row.rule_metadata and 'rule_platforms' in row.rule_metadata:
                platforms = row.rule_metadata.get('rule_platforms', [])
                for platform in platforms:
                    platform_counter[platform] += 1
        
        # Convert to sorted list
        rule_platforms = [
            {
                "value": platform,
                "label": f"{platform} ({count})",
                "count": count
            }
            for platform, count in platform_counter.most_common()
        ]
        
        return rule_platforms
    except Exception as e:
        logger.error(f"Error getting rule platforms filter: {e}")
        return []

def get_validation_statuses_filter(session) -> List[Dict[str, Any]]:
    """Get distinct validation statuses from rule metadata"""
    try:
        # Get validation statuses from metadata
        statuses_result = (
            session.query(
                text("rule_metadata->>'validation_status'").label('status'),
                func.count(DetectionRule.id).label('count')
            )
            .filter(text("rule_metadata ? 'validation_status'"))
            .group_by(text("rule_metadata->>'validation_status'"))
            .all()
        )
        
        return [
            {
                "value": status.status,
                "label": f"{status.status.replace('_', ' ').title()} ({status.count})",
                "count": status.count
            }
            for status in statuses_result
            if status.status
        ]
    except Exception as e:
        logger.error(f"Error getting validation statuses filter: {e}")
        return []

def get_popular_tags_filter(session, limit: int = 50) -> List[Dict[str, Any]]:
    """Get most popular tags from rules"""
    try:
        # Get all tags from rules
        tags_result = (
            session.query(DetectionRule.tags)
            .filter(DetectionRule.tags.isnot(None))
            .all()
        )
        
        # Flatten and count tags
        tag_counter = Counter()
        for row in tags_result:
            if row.tags:
                for tag in row.tags:
                    # Skip very long tags and system-generated tags
                    if len(tag) < 100 and not tag.startswith('mitre_technique:') and not tag.startswith('cve:'):
                        tag_counter[tag] += 1
        
        # Get top tags
        popular_tags = [
            {
                "value": tag,
                "label": f"{tag} ({count})",
                "count": count
            }
            for tag, count in tag_counter.most_common(limit)
        ]
        
        return popular_tags
    except Exception as e:
        logger.error(f"Error getting popular tags filter: {e}")
        return []

def get_cve_severities_filter(session) -> List[Dict[str, Any]]:
    """Get CVE severities for CVE filtering"""
    try:
        cve_severities = (
            session.query(
                CveEntry.severity,
                func.count(CveEntry.id).label('count')
            )
            .filter(CveEntry.severity.isnot(None))
            .group_by(CveEntry.severity)
            .order_by(CveEntry.severity)
            .all()
        )
        
        # Define severity order
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        
        result = []
        for sev in cve_severities:
            result.append({
                "value": sev.severity,
                "label": f"{sev.severity.capitalize()} ({sev.count})",
                "count": sev.count,
                "order": severity_order.get(sev.severity.lower(), 99)
            })
        
        # Sort by defined order
        result.sort(key=lambda x: x['order'])
        return result
    except Exception as e:
        logger.error(f"Error getting CVE severities filter: {e}")
        return []

def get_date_ranges_filter() -> List[Dict[str, Any]]:
    """Get predefined date range options"""
    return [
        {"value": "7", "label": "Last 7 days"},
        {"value": "30", "label": "Last 30 days"},
        {"value": "90", "label": "Last 3 months"},
        {"value": "180", "label": "Last 6 months"},
        {"value": "365", "label": "Last year"},
        {"value": "all", "label": "All time"}
    ]

def get_platforms() -> Dict[str, Any]:
    """Get detailed platform information"""
    try:
        with db_session() as session:
            platforms = get_platforms_filter(session)
            return create_api_response(200, {
                "platforms": platforms,
                "total": len(platforms)
            })
    except Exception as e:
        logger.error(f"Error getting platforms: {e}", exc_info=True)
        return create_error_response(500, "Failed to get platforms")

def get_rule_sources() -> Dict[str, Any]:
    """Get detailed rule source information"""
    try:
        with db_session() as session:
            sources = get_rule_sources_filter(session)
            
            # Add additional metadata
            enhanced_sources = []
            for source in sources:
                # Get last update time for this source
                last_update = (
                    session.query(func.max(DetectionRule.updated_date))
                    .filter(DetectionRule.source_id == int(source['value']))
                    .scalar()
                )
                
                enhanced_source = {
                    **source,
                    "last_update": last_update.isoformat() if last_update else None
                }
                enhanced_sources.append(enhanced_source)
            
            return create_api_response(200, {
                "rule_sources": enhanced_sources,
                "total": len(enhanced_sources)
            })
    except Exception as e:
        logger.error(f"Error getting rule sources: {e}", exc_info=True)
        return create_error_response(500, "Failed to get rule sources")

def get_filter_summary() -> Dict[str, Any]:
    """Get summary of all available filters"""
    try:
        with db_session() as session:
            summary = {
                "rule_sources": len(get_rule_sources_filter(session)),
                "rule_types": len(get_rule_types_filter(session)),
                "severities": len(get_severities_filter(session)),
                "tactics": len(get_tactics_filter(session)),
                "platforms": len(get_platforms_filter(session)),
                "rule_platforms": len(get_rule_platforms_filter(session)),
                "validation_statuses": len(get_validation_statuses_filter(session)),
                "popular_tags": len(get_popular_tags_filter(session, limit=100)),
                "cve_severities": len(get_cve_severities_filter(session))
            }
            
            return create_api_response(200, {
                "filter_summary": summary,
                "total_filter_options": sum(summary.values())
            })
    except Exception as e:
        logger.error(f"Error getting filter summary: {e}", exc_info=True)
        return create_error_response(500, "Failed to get filter summary")