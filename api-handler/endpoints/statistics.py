# endpoints/statistics.py
"""
Enhanced statistics-related endpoint handlers.
Provides comprehensive dashboard data and analytics.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_, text, desc
from collections import defaultdict

from saint_datamodel import db_session
from saint_datamodel.models import (
    RuleSource, DetectionRule, MitreTechnique, MitreTactic, CveEntry,
    RuleMitreMapping, RuleCveMapping
)
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)

def validate_stats_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate statistics parameters"""
    validated = {}
    
    # Date range
    validated['days_back'] = min(max(1, params.get('days_back', 30)), 365)
    
    # Filters for scoped statistics
    validated['source_ids'] = params.get('source_ids', [])
    validated['rule_types'] = params.get('rule_types', [])
    validated['severities'] = params.get('severities', [])
    validated['is_active'] = None
    if params.get('is_active') is not None:
        validated['is_active'] = str(params.get('is_active')).lower() in ['true', '1', 'yes']
    
    return validated

def apply_rule_filters(query, filters: Dict[str, Any]):
    """Apply common rule filters to a query"""
    if filters.get('source_ids'):
        source_ids = [int(sid) for sid in filters['source_ids'] if str(sid).isdigit()]
        if source_ids:
            query = query.filter(DetectionRule.source_id.in_(source_ids))
    
    if filters.get('rule_types'):
        query = query.filter(DetectionRule.rule_type.in_(filters['rule_types']))
    
    if filters.get('severities'):
        query = query.filter(DetectionRule.severity.in_(filters['severities']))
    
    if filters.get('is_active') is not None:
        query = query.filter(DetectionRule.is_active == filters['is_active'])
    
    return query

def handle_get_stats(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get dashboard statistics with optional filters.
    Enhanced to work with improved data processing.
    """
    try:
        # Validate parameters
        filters = validate_stats_params(params)
        
        with db_session() as session:
            # Build base query with filters
            base_query = session.query(DetectionRule)
            base_query = apply_rule_filters(base_query, filters)
            
            # Get total rule count
            total_rules = base_query.count()
            
            if total_rules == 0:
                return create_api_response(200, {
                    "total_rules": 0,
                    "message": "No rules found matching the specified filters",
                    "filters": filters
                })
            
            # Get statistics
            stats = {
                "total_rules": total_rules,
                "stats": {},
                "enrichment": {},
                "active_filters": {k: v for k, v in filters.items() if v is not None and v != []}
            }
            
            # Rules by severity
            severity_stats = (
                apply_rule_filters(
                    session.query(
                        DetectionRule.severity,
                        func.count(DetectionRule.id)
                    ), filters
                )
                .filter(DetectionRule.severity.isnot(None))
                .group_by(DetectionRule.severity)
                .all()
            )
            stats["stats"]["by_severity"] = {sev: count for sev, count in severity_stats}
            
            # Rules by source
            source_stats = (
                apply_rule_filters(
                    session.query(
                        RuleSource.name,
                        func.count(DetectionRule.id)
                    ), filters
                )
                .join(RuleSource)
                .group_by(RuleSource.name)
                .all()
            )
            stats["stats"]["by_rule_source"] = {name: count for name, count in source_stats}
            
            # Rules by type
            type_stats = (
                apply_rule_filters(
                    session.query(
                        DetectionRule.rule_type,
                        func.count(DetectionRule.id)
                    ), filters
                )
                .filter(DetectionRule.rule_type.isnot(None))
                .group_by(DetectionRule.rule_type)
                .all()
            )
            stats["stats"]["by_rule_type"] = {rt: count for rt, count in type_stats}
            
            # Rule platforms (from metadata)
            platform_rules = (
                apply_rule_filters(
                    session.query(DetectionRule.rule_metadata), filters
                )
                .filter(text("rule_metadata ? 'rule_platforms'"))
                .all()
            )
            
            platform_counts = defaultdict(int)
            for row in platform_rules:
                if row.rule_metadata and 'rule_platforms' in row.rule_metadata:
                    platforms = row.rule_metadata.get('rule_platforms', [])
                    for platform in platforms:
                        platform_counts[platform] += 1
            
            stats["stats"]["by_rule_platform"] = dict(platform_counts)
            
            # Enrichment statistics
            stats["enrichment"] = get_enrichment_stats(session, filters)
            
            # Recent activity
            stats["recent_activity"] = get_recent_activity_stats(session, filters)
            
            return create_api_response(200, stats)

    except Exception as e:
        logger.error(f"Error generating statistics: {e}", exc_info=True)
        return create_error_response(500, "Failed to generate statistics")

def get_enrichment_stats(session, filters: Dict[str, Any]) -> Dict[str, Any]:
    """Get enrichment statistics for rules"""
    try:
        base_query = session.query(DetectionRule)
        base_query = apply_rule_filters(base_query, filters)
        
        # MITRE enrichment
        mitre_mapped_count = (
            apply_rule_filters(
                session.query(func.count(DetectionRule.id.distinct())), filters
            )
            .join(RuleMitreMapping)
            .scalar()
        )
        
        mitre_metadata_count = (
            apply_rule_filters(session.query(func.count(DetectionRule.id)), filters)
            .filter(text("jsonb_array_length(rule_metadata->'extracted_mitre_techniques') > 0"))
            .scalar()
        )
        
        # CVE enrichment
        cve_mapped_count = (
            apply_rule_filters(
                session.query(func.count(DetectionRule.id.distinct())), filters
            )
            .join(RuleCveMapping)
            .scalar()
        )
        
        cve_metadata_count = (
            apply_rule_filters(session.query(func.count(DetectionRule.id)), filters)
            .filter(text("jsonb_array_length(rule_metadata->'extracted_cve_ids') > 0"))
            .scalar()
        )
        
        total_rules = base_query.count()
        
        return {
            "mitre": {
                "with_mappings": mitre_mapped_count or 0,
                "with_metadata": mitre_metadata_count or 0,
                "total_enriched": max(mitre_mapped_count or 0, mitre_metadata_count or 0),
                "coverage_percentage": round((max(mitre_mapped_count or 0, mitre_metadata_count or 0) / total_rules * 100), 2) if total_rules > 0 else 0
            },
            "cve": {
                "with_mappings": cve_mapped_count or 0,
                "with_metadata": cve_metadata_count or 0,
                "total_enriched": max(cve_mapped_count or 0, cve_metadata_count or 0),
                "coverage_percentage": round((max(cve_mapped_count or 0, cve_metadata_count or 0) / total_rules * 100), 2) if total_rules > 0 else 0
            }
        }
    except Exception as e:
        logger.error(f"Error getting enrichment stats: {e}")
        return {"mitre": {}, "cve": {}}

def get_recent_activity_stats(session, filters: Dict[str, Any]) -> Dict[str, Any]:
    """Get recent activity statistics"""
    try:
        # Rules created/updated in the last 7 days
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        
        recent_created = (
            apply_rule_filters(session.query(func.count(DetectionRule.id)), filters)
            .filter(DetectionRule.created_date >= seven_days_ago)
            .scalar()
        )
        
        recent_updated = (
            apply_rule_filters(session.query(func.count(DetectionRule.id)), filters)
            .filter(DetectionRule.updated_date >= seven_days_ago)
            .filter(DetectionRule.created_date < seven_days_ago)  # Exclude newly created
            .scalar()
        )
        
        return {
            "rules_created_7_days": recent_created or 0,
            "rules_updated_7_days": recent_updated or 0,
            "total_activity_7_days": (recent_created or 0) + (recent_updated or 0)
        }
    except Exception as e:
        logger.error(f"Error getting recent activity stats: {e}")
        return {}

def get_dashboard_data(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get comprehensive dashboard data"""
    try:
        filters = validate_stats_params(params)
        
        with db_session() as session:
            dashboard = {
                "overview": {},
                "charts": {},
                "recent_activity": {},
                "alerts": [],
                "metadata": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "filters_applied": filters
                }
            }
            
            # Overview metrics
            dashboard["overview"] = get_overview_metrics(session, filters)
            
            # Chart data
            dashboard["charts"] = get_chart_data(session, filters)
            
            # Recent activity
            dashboard["recent_activity"] = get_detailed_recent_activity(session, filters)
            
            # Alerts/notifications
            dashboard["alerts"] = get_dashboard_alerts(session, filters)
            
            return create_api_response(200, dashboard)

    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}", exc_info=True)
        return create_error_response(500, "Failed to get dashboard data")

def get_overview_metrics(session, filters: Dict[str, Any]) -> Dict[str, Any]:
    """Get key overview metrics"""
    base_query = session.query(DetectionRule)
    base_query = apply_rule_filters(base_query, filters)
    
    total_rules = base_query.count()
    active_rules = base_query.filter(DetectionRule.is_active == True).count()
    
    # MITRE coverage
    mitre_covered = (
        apply_rule_filters(
            session.query(func.count(DetectionRule.id.distinct())), filters
        )
        .join(RuleMitreMapping)
        .scalar() or 0
    )
    
    # CVE coverage
    cve_covered = (
        apply_rule_filters(
            session.query(func.count(DetectionRule.id.distinct())), filters
        )
        .join(RuleCveMapping)
        .scalar() or 0
    )
    
    # Total unique MITRE techniques covered
    total_techniques_covered = (
        session.query(func.count(MitreTechnique.id.distinct()))
        .join(RuleMitreMapping)
        .join(DetectionRule)
        .filter(DetectionRule.is_active == True)
        .scalar() or 0
    )
    
    # Total MITRE techniques available
    total_techniques_available = session.query(func.count(MitreTechnique.id)).scalar() or 1
    
    return {
        "total_rules": total_rules,
        "active_rules": active_rules,
        "inactive_rules": total_rules - active_rules,
        "mitre_coverage": {
            "rules_with_mitre": mitre_covered,
            "techniques_covered": total_techniques_covered,
            "total_techniques": total_techniques_available,
            "coverage_percentage": round((total_techniques_covered / total_techniques_available * 100), 2)
        },
        "cve_coverage": {
            "rules_with_cves": cve_covered,
            "coverage_percentage": round((cve_covered / total_rules * 100), 2) if total_rules > 0 else 0
        }
    }

def get_chart_data(session, filters: Dict[str, Any]) -> Dict[str, Any]:
    """Get data for dashboard charts"""
    charts = {}
    
    # Severity distribution (pie chart)
    severity_data = (
        apply_rule_filters(
            session.query(
                DetectionRule.severity,
                func.count(DetectionRule.id)
            ), filters
        )
        .filter(DetectionRule.severity.isnot(None))
        .group_by(DetectionRule.severity)
        .all()
    )
    
    charts["severity_distribution"] = [
        {"name": sev, "value": count}
        for sev, count in severity_data
    ]
    
    # Rules by source (bar chart)
    source_data = (
        apply_rule_filters(
            session.query(
                RuleSource.name,
                func.count(DetectionRule.id)
            ), filters
        )
        .join(RuleSource)
        .group_by(RuleSource.name)
        .order_by(func.count(DetectionRule.id).desc())
        .limit(10)  # Top 10 sources
        .all()
    )
    
    charts["rules_by_source"] = [
        {"name": name, "value": count}
        for name, count in source_data
    ]
    
    # MITRE coverage heatmap data (top tactics)
    tactic_coverage = (
        session.query(
            MitreTactic.name,
            func.count(DetectionRule.id.distinct()).label('rule_count')
        )
        .join(MitreTechnique)
        .join(RuleMitreMapping)
        .join(DetectionRule)
        .filter(DetectionRule.is_active == True)
        .group_by(MitreTactic.name)
        .order_by(func.count(DetectionRule.id.distinct()).desc())
        .limit(10)
        .all()
    )
    
    charts["mitre_tactic_coverage"] = [
        {"tactic": tactic, "rules": count}
        for tactic, count in tactic_coverage
    ]
    
    return charts

def get_detailed_recent_activity(session, filters: Dict[str, Any]) -> Dict[str, Any]:
    """Get detailed recent activity information"""
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    
    # Recent rules
    recent_rules = (
        apply_rule_filters(session.query(DetectionRule), filters)
        .options(session.query(DetectionRule).options(
            session.query(DetectionRule.source).load_only('name')
        ))
        .filter(DetectionRule.created_date >= seven_days_ago)
        .order_by(desc(DetectionRule.created_date))
        .limit(10)
        .all()
    )
    
    # Recent updates
    recent_updates = (
        apply_rule_filters(session.query(DetectionRule), filters)
        .filter(DetectionRule.updated_date >= seven_days_ago)
        .filter(DetectionRule.created_date < seven_days_ago)
        .order_by(desc(DetectionRule.updated_date))
        .limit(10)
        .all()
    )
    
    return {
        "recent_rules": [
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "severity": rule.severity,
                "created_date": rule.created_date.isoformat() if rule.created_date else None
            }
            for rule in recent_rules
        ],
        "recent_updates": [
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "severity": rule.severity,
                "updated_date": rule.updated_date.isoformat() if rule.updated_date else None
            }
            for rule in recent_updates
        ]
    }

def get_dashboard_alerts(session, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get dashboard alerts and notifications"""
    alerts = []
    
    try:
        # Check for rules without MITRE mappings
        rules_without_mitre = (
            apply_rule_filters(
                session.query(func.count(DetectionRule.id)), filters
            )
            .outerjoin(RuleMitreMapping)
            .filter(RuleMitreMapping.id.is_(None))
            .filter(
                or_(
                    text("rule_metadata->'extracted_mitre_techniques' IS NULL"),
                    text("jsonb_array_length(rule_metadata->'extracted_mitre_techniques') = 0")
                )
            )
            .scalar()
        )
        
        if rules_without_mitre > 0:
            alerts.append({
                "type": "warning",
                "title": "Rules Missing MITRE Mappings",
                "message": f"{rules_without_mitre} rules have no MITRE ATT&CK technique mappings",
                "action": "Review and enhance rule mappings"
            })
        
        # Check for recent high-severity CVEs without coverage
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        recent_high_cves = (
            session.query(func.count(CveEntry.id))
            .filter(CveEntry.published_date >= seven_days_ago)
            .filter(CveEntry.cvss_v3_score >= 7.0)
            .outerjoin(RuleCveMapping)
            .filter(RuleCveMapping.id.is_(None))
            .scalar()
        )
        
        if recent_high_cves > 0:
            alerts.append({
                "type": "error",
                "title": "Uncovered High-Severity CVEs",
                "message": f"{recent_high_cves} high-severity CVEs from the last 7 days have no rule coverage",
                "action": "Create detection rules for recent vulnerabilities"
            })
        
        # Check for inactive rules
        total_rules = apply_rule_filters(session.query(func.count(DetectionRule.id)), filters).scalar()
        inactive_rules = (
            apply_rule_filters(session.query(func.count(DetectionRule.id)), filters)
            .filter(DetectionRule.is_active == False)
            .scalar()
        )
        
        if inactive_rules > 0 and total_rules > 0:
            inactive_percentage = (inactive_rules / total_rules) * 100
            if inactive_percentage > 20:  # More than 20% inactive
                alerts.append({
                    "type": "info",
                    "title": "High Number of Inactive Rules",
                    "message": f"{inactive_percentage:.1f}% of rules are currently inactive",
                    "action": "Review inactive rules and reactivate if needed"
                })
        
    except Exception as e:
        logger.error(f"Error generating dashboard alerts: {e}")
    
    return alerts

def get_trend_analysis(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get trend analysis data"""
    try:
        days_back = min(max(7, params.get('days_back', 30)), 90)
        
        with db_session() as session:
            # Daily rule creation trend
            start_date = datetime.utcnow() - timedelta(days=days_back)
            
            daily_stats = []
            for i in range(days_back):
                day_start = start_date + timedelta(days=i)
                day_end = day_start + timedelta(days=1)
                
                rules_created = (
                    session.query(func.count(DetectionRule.id))
                    .filter(DetectionRule.created_date >= day_start)
                    .filter(DetectionRule.created_date < day_end)
                    .scalar()
                )
                
                rules_updated = (
                    session.query(func.count(DetectionRule.id))
                    .filter(DetectionRule.updated_date >= day_start)
                    .filter(DetectionRule.updated_date < day_end)
                    .filter(DetectionRule.created_date < day_start)  # Exclude newly created
                    .scalar()
                )
                
                daily_stats.append({
                    "date": day_start.strftime("%Y-%m-%d"),
                    "rules_created": rules_created or 0,
                    "rules_updated": rules_updated or 0,
                    "total_activity": (rules_created or 0) + (rules_updated or 0)
                })
            
            trend_data = {
                "period_days": days_back,
                "daily_stats": daily_stats,
                "summary": {
                    "total_created": sum(d["rules_created"] for d in daily_stats),
                    "total_updated": sum(d["rules_updated"] for d in daily_stats),
                    "most_active_day": max(daily_stats, key=lambda x: x["total_activity"])["date"] if daily_stats else None
                }
            }
            
            return create_api_response(200, trend_data)

    except Exception as e:
        logger.error(f"Error getting trend analysis: {e}", exc_info=True)
        return create_error_response(500, "Failed to get trend analysis")