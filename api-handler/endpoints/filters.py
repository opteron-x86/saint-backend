# endpoints/filters.py
"""
Filter options endpoint handler for UI filter controls
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
    """Get comprehensive filter options for UI filter controls"""
    try:
        with db_session() as session:
            filter_options = {}
            
            filter_options['rule_sources'] = get_rule_sources_filter(session)
            filter_options['severities'] = get_severities_filter(session)
            filter_options['tactics'] = get_tactics_filter(session)
            filter_options['platforms'] = get_platforms_filter(session)
            filter_options['rule_platforms'] = get_rule_platforms_filter(session)
            filter_options['popular_tags'] = get_popular_tags_filter(session)
            filter_options['cve_severities'] = get_cve_severities_filter(session)
            filter_options['date_ranges'] = get_date_ranges_filter()
            
            # Add empty arrays for unused filters to prevent frontend errors
            filter_options['mitre_techniques'] = []
            filter_options['enrichment_levels'] = []
            filter_options['validation_statuses'] = []  # Keep empty for compatibility
            
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
                "count": source.rule_count
            }
            for source in sources_with_counts
        ]
    except Exception as e:
        logger.error(f"Error getting rule sources filter: {e}")
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
            .all()
        )
        
        # Standard severity order
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
        
        result = []
        for sev in severities:
            if sev.severity:
                result.append({
                    "value": sev.severity.lower(),
                    "label": f"{sev.severity.upper()} ({sev.count})",
                    "count": sev.count
                })
        
        # Sort by standard severity order
        result.sort(key=lambda x: severity_order.get(x['value'], 999))
        return result
        
    except Exception as e:
        logger.error(f"Error getting severities filter: {e}")
        return []

def get_tactics_filter(session) -> List[Dict[str, Any]]:
    """Get MITRE tactics with rule counts"""
    try:
        tactics = (
            session.query(
                MitreTactic.name,
                func.count(distinct(RuleMitreMapping.rule_id)).label('count')
            )
            .join(MitreTechnique, MitreTactic.id == MitreTechnique.tactic_id)
            .join(RuleMitreMapping, MitreTechnique.id == RuleMitreMapping.technique_id)
            .group_by(MitreTactic.name)
            .order_by(MitreTactic.name)
            .all()
        )
        
        return [
            {
                "value": tactic.name,
                "label": f"{tactic.name} ({tactic.count})",
                "count": tactic.count
            }
            for tactic in tactics
        ]
    except Exception as e:
        logger.error(f"Error getting tactics filter: {e}")
        return []

def get_platforms_filter(session) -> List[Dict[str, Any]]:
    """Get platforms from MITRE techniques"""
    try:
        # Get all platforms from MITRE techniques
        techniques = session.query(MitreTechnique.platforms).filter(
            MitreTechnique.platforms.isnot(None)
        ).all()
        
        platform_counts = Counter()
        for tech in techniques:
            if tech.platforms:
                for platform in tech.platforms:
                    platform_counts[platform] += 1
        
        return [
            {
                "value": platform,
                "label": f"{platform} ({count})",
                "count": count
            }
            for platform, count in sorted(platform_counts.items())
        ]
    except Exception as e:
        logger.error(f"Error getting platforms filter: {e}")
        return []

def get_rule_platforms_filter(session) -> List[Dict[str, Any]]:
    """Get platforms from rule metadata"""
    try:
        # Query rules with rule_platforms in metadata
        rules = session.query(DetectionRule.rule_metadata).filter(
            DetectionRule.rule_metadata.isnot(None)
        ).all()
        
        platform_counts = Counter()
        for rule in rules:
            if rule.rule_metadata and 'rule_platforms' in rule.rule_metadata:
                platforms = rule.rule_metadata.get('rule_platforms', [])
                if isinstance(platforms, list):
                    for platform in platforms:
                        platform_counts[platform] += 1
        
        return [
            {
                "value": platform,
                "label": f"{platform} ({count})",
                "count": count
            }
            for platform, count in sorted(platform_counts.items())
        ]
    except Exception as e:
        logger.error(f"Error getting rule platforms filter: {e}")
        return []

def get_popular_tags_filter(session, limit: int = 20) -> List[Dict[str, Any]]:
    """Get most popular tags"""
    try:
        rules_with_tags = session.query(DetectionRule.tags).filter(
            DetectionRule.tags.isnot(None)
        ).all()
        
        tag_counts = Counter()
        for rule in rules_with_tags:
            if rule.tags:
                for tag in rule.tags:
                    tag_counts[tag] += 1
        
        # Get top tags
        top_tags = tag_counts.most_common(limit)
        
        return [
            {
                "value": tag,
                "label": f"{tag} ({count})",
                "count": count
            }
            for tag, count in top_tags
        ]
    except Exception as e:
        logger.error(f"Error getting popular tags filter: {e}")
        return []

def get_cve_severities_filter(session) -> List[Dict[str, Any]]:
    """Get CVE severities with counts"""
    try:
        cve_severities = (
            session.query(
                CveEntry.severity,
                func.count(CveEntry.id).label('count')
            )
            .filter(CveEntry.severity.isnot(None))
            .group_by(CveEntry.severity)
            .all()
        )
        
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        
        result = []
        for sev in cve_severities:
            if sev.severity:
                result.append({
                    "value": sev.severity.lower(),
                    "label": f"{sev.severity.upper()} ({sev.count})",
                    "count": sev.count
                })
        
        result.sort(key=lambda x: severity_order.get(x['value'], 999))
        return result
        
    except Exception as e:
        logger.error(f"Error getting CVE severities filter: {e}")
        return []

def get_date_ranges_filter() -> List[Dict[str, Any]]:
    """Get predefined date range options"""
    return [
        {"value": "today", "label": "Today"},
        {"value": "yesterday", "label": "Yesterday"},
        {"value": "last_7_days", "label": "Last 7 Days"},
        {"value": "last_30_days", "label": "Last 30 Days"},
        {"value": "last_90_days", "label": "Last 90 Days"},
        {"value": "this_month", "label": "This Month"},
        {"value": "last_month", "label": "Last Month"},
        {"value": "custom", "label": "Custom Range"}
    ]

def handle_get_rule_sources() -> Dict[str, Any]:
    """Get detailed rule sources information"""
    try:
        with db_session() as session:
            sources = session.query(
                RuleSource.id,
                RuleSource.name,
                RuleSource.source_type,
                RuleSource.description,
                RuleSource.is_active,
                RuleSource.last_updated,
                func.count(DetectionRule.id).label('rule_count'),
                func.max(DetectionRule.updated_date).label('latest_rule_update')
            ).outerjoin(
                DetectionRule
            ).group_by(
                RuleSource.id,
                RuleSource.name,
                RuleSource.source_type,
                RuleSource.description,
                RuleSource.is_active,
                RuleSource.last_updated
            ).all()
            
            enhanced_sources = []
            for source in sources:
                enhanced_sources.append({
                    "id": source.id,
                    "name": source.name,
                    "source_type": source.source_type,
                    "description": source.description,
                    "is_active": source.is_active,
                    "rule_count": source.rule_count,
                    "last_updated": source.last_updated.isoformat() if source.last_updated else None,
                    "latest_rule_update": source.latest_rule_update.isoformat() if source.latest_rule_update else None
                })
            
            return create_api_response(200, {
                "rule_sources": enhanced_sources,
                "total": len(enhanced_sources)
            })
    except Exception as e:
        logger.error(f"Error getting rule sources: {e}", exc_info=True)
        return create_error_response(500, "Failed to get rule sources")