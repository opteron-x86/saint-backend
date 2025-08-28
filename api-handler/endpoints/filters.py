# endpoints/filters.py
"""
Enhanced filter options endpoint with proper SIEM platform handling
"""

import logging
from typing import Dict, Any, List
from sqlalchemy import func, text
from collections import Counter, defaultdict

from saint_datamodel import db_session
from saint_datamodel.models import (
    RuleSource, DetectionRule, MitreTactic, MitreTechnique,
    CveEntry, RuleMitreMapping, RuleCveMapping
)
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)

def get_filter_options() -> Dict[str, Any]:
    """Get comprehensive filter options with SIEM platform grouping"""
    try:
        with db_session() as session:
            filter_options = {}
            
            # Rule Sources - grouped by type
            filter_options['rule_sources'] = get_rule_sources_filter(session)
            
            # SIEM Platforms - extracted from metadata
            filter_options['siem_platforms'] = get_siem_platforms_filter(session)
            
            # Rule Types
            filter_options['rule_types'] = get_rule_types_filter(session)
            
            # Severities
            filter_options['severities'] = get_severities_filter(session)
            
            # MITRE Tactics
            filter_options['tactics'] = get_tactics_filter(session)
            
            # Platforms from MITRE
            filter_options['platforms'] = get_platforms_filter(session)
            
            # Rule Platforms from metadata
            filter_options['rule_platforms'] = get_rule_platforms_filter(session)
            
            # Areas of Responsibility
            filter_options['areas_of_responsibility'] = get_aor_filter(session)
            
            # Data Sources
            filter_options['data_sources'] = get_data_sources_filter(session)
            
            # Information Controls
            filter_options['info_controls'] = get_info_controls_filter(session)
            
            # Popular Tags
            filter_options['popular_tags'] = get_popular_tags_filter(session)
            
            # Date Ranges
            filter_options['date_ranges'] = get_date_ranges_filter()
            
            return create_api_response(200, filter_options)

    except Exception as e:
        logger.error(f"Error getting filter options: {e}", exc_info=True)
        return create_error_response(500, "Failed to get filter options")

def get_rule_sources_filter(session) -> List[Dict[str, Any]]:
    """Get rule sources grouped by type"""
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
            .order_by(RuleSource.source_type, RuleSource.name)
            .all()
        )
        
        # Group Elastic sources for better display
        source_groups = defaultdict(list)
        elastic_total = 0
        
        for source in sources_with_counts:
            # Special handling for Elastic sources
            if source.name.endswith('-ELASTIC'):
                elastic_total += source.rule_count
                source_groups['Elastic'].append({
                    "value": str(source.id),
                    "label": source.name.replace('-ELASTIC', ''),
                    "count": source.rule_count
                })
            else:
                # Regular sources
                source_groups[source.source_type].append({
                    "value": str(source.id),
                    "label": source.name,
                    "count": source.rule_count
                })
        
        # Build final list with Elastic grouped
        result = []
        
        # Add grouped Elastic if exists
        if 'Elastic' in source_groups:
            elastic_ids = [s['value'] for s in source_groups['Elastic']]
            result.append({
                "value": ','.join(elastic_ids),  # Comma-separated IDs for multi-select
                "label": f"Elastic SIEM ({elastic_total})",
                "source_type": "SIEM",
                "rule_count": elastic_total,
                "children": source_groups['Elastic']  # Sub-options
            })
        
        # Add other sources
        for source_type, sources in source_groups.items():
            if source_type != 'Elastic':
                for source in sources:
                    result.append({
                        "value": source['value'],
                        "label": f"{source['label']} ({source['count']})",
                        "source_type": source_type,
                        "rule_count": source['count']
                    })
        
        return sorted(result, key=lambda x: (-x['rule_count'], x['label']))
        
    except Exception as e:
        logger.error(f"Error getting rule sources filter: {e}")
        return []

def get_siem_platforms_filter(session) -> List[Dict[str, Any]]:
    """Get SIEM platforms from rule metadata"""
    try:
        siem_query = session.query(
            func.jsonb_extract_path_text(DetectionRule.rule_metadata, 'siem_platform').label('siem'),
            func.count(DetectionRule.id).label('count')
        ).filter(
            DetectionRule.rule_metadata.isnot(None),
            text("rule_metadata->>'siem_platform' IS NOT NULL")
        ).group_by('siem').all()
        
        platforms = []
        for siem, count in siem_query:
            if siem:
                # Format display name
                display_name = siem
                if siem in ['gms-elastic', 'td-elastic']:
                    display_name = siem.upper().replace('-', ' ')
                
                platforms.append({
                    "value": siem,
                    "label": f"{display_name} ({count})",
                    "count": count
                })
        
        return sorted(platforms, key=lambda x: (-x['count'], x['label']))
        
    except Exception as e:
        logger.error(f"Error getting SIEM platforms filter: {e}")
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
            .order_by(func.count(DetectionRule.id).desc())
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
    """Get distinct severities with counts and proper ordering"""
    try:
        severity_stats = (
            session.query(
                DetectionRule.severity,
                func.count(DetectionRule.id).label('count')
            )
            .filter(DetectionRule.severity.isnot(None))
            .group_by(DetectionRule.severity)
            .all()
        )
        
        # Order by severity level
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        
        severities = [
            {
                "value": sev.severity,
                "label": f"{sev.severity.capitalize()} ({sev.count})",
                "count": sev.count,
                "order": severity_order.get(sev.severity, 99)
            }
            for sev in severity_stats
        ]
        
        return sorted(severities, key=lambda x: x['order'])
        
    except Exception as e:
        logger.error(f"Error getting severities filter: {e}")
        return []

def get_tactics_filter(session) -> List[Dict[str, Any]]:
    """Get MITRE tactics with rule counts"""
    try:
        tactics = (
            session.query(
                MitreTactic.name,
                MitreTactic.tactic_id,
                func.count(DetectionRule.id.distinct()).label('rule_count')
            )
            .join(MitreTechnique, MitreTactic.id == MitreTechnique.tactic_id)
            .join(RuleMitreMapping, MitreTechnique.id == RuleMitreMapping.technique_id)
            .join(DetectionRule, RuleMitreMapping.rule_id == DetectionRule.id)
            .filter(DetectionRule.is_active == True)
            .group_by(MitreTactic.id, MitreTactic.name, MitreTactic.tactic_id)
            .order_by(func.count(DetectionRule.id.distinct()).desc())
            .all()
        )
        
        return [
            {
                "value": tactic.name,
                "label": f"{tactic.name} ({tactic.rule_count})",
                "tactic_id": tactic.tactic_id,
                "rule_count": tactic.rule_count
            }
            for tactic in tactics
        ]
    except Exception as e:
        logger.error(f"Error getting tactics filter: {e}")
        return []

def get_platforms_filter(session) -> List[Dict[str, Any]]:
    """Get platforms from MITRE techniques"""
    try:
        platforms_result = (
            session.query(func.unnest(MitreTechnique.platforms).label('platform'))
            .distinct()
            .all()
        )
        
        platforms = sorted(set(p.platform for p in platforms_result if p.platform))
        
        # Count rules per platform
        platform_counts = {}
        for platform in platforms:
            count = (
                session.query(func.count(DetectionRule.id.distinct()))
                .join(RuleMitreMapping)
                .join(MitreTechnique)
                .filter(text(":platform = ANY(platforms)"))
                .params(platform=platform)
                .scalar()
            )
            platform_counts[platform] = count or 0
        
        return [
            {
                "value": platform,
                "label": f"{platform} ({platform_counts[platform]})",
                "count": platform_counts[platform]
            }
            for platform in sorted(platforms, key=lambda p: -platform_counts[p])
        ]
    except Exception as e:
        logger.error(f"Error getting platforms filter: {e}")
        return []

def get_rule_platforms_filter(session) -> List[Dict[str, Any]]:
    """Get rule platforms from metadata"""
    try:
        rules_with_platforms = (
            session.query(DetectionRule.rule_metadata)
            .filter(text("rule_metadata->'rule_platforms' IS NOT NULL"))
            .filter(text("jsonb_array_length(rule_metadata->'rule_platforms') > 0"))
            .all()
        )
        
        platform_counter = Counter()
        for row in rules_with_platforms:
            if row.rule_metadata and 'rule_platforms' in row.rule_metadata:
                platforms = row.rule_metadata.get('rule_platforms', [])
                for platform in platforms:
                    platform_counter[platform] += 1
        
        return [
            {
                "value": platform,
                "label": f"{platform} ({count})",
                "count": count
            }
            for platform, count in platform_counter.most_common()
        ]
    except Exception as e:
        logger.error(f"Error getting rule platforms filter: {e}")
        return []

def get_aor_filter(session) -> List[Dict[str, Any]]:
    """Get Areas of Responsibility from metadata"""
    try:
        aor_query = session.query(
            func.jsonb_extract_path_text(DetectionRule.rule_metadata, 'aor').label('aor'),
            func.count(DetectionRule.id).label('count')
        ).filter(
            DetectionRule.rule_metadata.isnot(None),
            text("rule_metadata->>'aor' IS NOT NULL")
        ).group_by('aor').all()
        
        return [
            {
                "value": aor,
                "label": f"{aor} ({count})",
                "count": count
            }
            for aor, count in aor_query if aor
        ]
    except Exception as e:
        logger.error(f"Error getting AOR filter: {e}")
        return []

def get_data_sources_filter(session) -> List[Dict[str, Any]]:
    """Get data sources from metadata"""
    try:
        rules_with_sources = session.query(DetectionRule.rule_metadata).filter(
            text("rule_metadata->'data_sources' IS NOT NULL")
        ).all()
        
        source_counter = Counter()
        for row in rules_with_sources:
            if row.rule_metadata and 'data_sources' in row.rule_metadata:
                sources = row.rule_metadata.get('data_sources', [])
                for source in sources:
                    source_counter[source] += 1
        
        return [
            {
                "value": ds,
                "label": f"{ds} ({source_counter[ds]})",
                "count": source_counter[ds]
            }
            for ds in sorted(source_counter.keys())
        ]
    except Exception as e:
        logger.error(f"Error getting data sources filter: {e}")
        return []

def get_info_controls_filter(session) -> List[Dict[str, Any]]:
    """Get information control markings from metadata"""
    try:
        controls_query = session.query(
            func.jsonb_extract_path_text(DetectionRule.rule_metadata, 'info_controls').label('control'),
            func.count(DetectionRule.id).label('count')
        ).filter(
            DetectionRule.rule_metadata.isnot(None),
            text("rule_metadata->>'info_controls' IS NOT NULL")
        ).group_by('control').all()
        
        return [
            {
                "value": control,
                "label": f"{control} ({count})",
                "count": count
            }
            for control, count in controls_query if control
        ]
    except Exception as e:
        logger.error(f"Error getting info controls filter: {e}")
        return []

def get_popular_tags_filter(session, limit: int = 20) -> List[Dict[str, Any]]:
    """Get most popular tags excluding system tags"""
    try:
        tags_result = session.query(DetectionRule.tags).filter(
            DetectionRule.tags.isnot(None)
        ).all()
        
        tag_counter = Counter()
        for row in tags_result:
            if row.tags:
                for tag in row.tags:
                    # Skip system-generated tags
                    if not any(tag.startswith(prefix) for prefix in 
                              ['mitre_technique:', 'cve:', 'source:', 'platform:', 
                               'rule_type:', 'severity:', 'siem:']):
                        if len(tag) < 50:  # Skip very long tags
                            tag_counter[tag] += 1
        
        return [
            {
                "value": tag,
                "label": f"{tag} ({count})",
                "count": count
            }
            for tag, count in tag_counter.most_common(limit)
        ]
    except Exception as e:
        logger.error(f"Error getting popular tags filter: {e}")
        return []

def get_date_ranges_filter() -> List[Dict[str, Any]]:
    """Get predefined date range options"""
    return [
        {"value": "7", "label": "Last 7 days"},
        {"value": "30", "label": "Last 30 days"},
        {"value": "90", "label": "Last 90 days"},
        {"value": "180", "label": "Last 6 months"},
        {"value": "365", "label": "Last year"},
        {"value": "all", "label": "All time"}
    ]