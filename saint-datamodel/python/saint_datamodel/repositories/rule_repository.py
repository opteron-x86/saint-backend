"""
Repository for detection rules with specialized queries
Enhanced to work with improved data extraction and enrichment
"""

from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta

from sqlalchemy import and_, or_, func, desc, asc, text
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy.dialects.postgresql import ARRAY

from .base import BaseRepository
from ..models.rules import DetectionRule, RulePerformance, RuleCategory, RuleCategoryMapping, RuleSource
from ..models.mitre import MitreTechnique, MitreTactic
from ..models.vulnerabilities import CveEntry
from ..models.relationships import RuleMitreMapping, RuleCveMapping, RuleIocMapping

class RuleRepository(BaseRepository[DetectionRule]):
    """Repository for detection rules with specialized queries"""
    
    def __init__(self, session: Session):
        super().__init__(session, DetectionRule)
    
    def get_by_hash(self, hash_value: str) -> Optional[DetectionRule]:
        """Get rule by content hash"""
        return self.session.query(DetectionRule).filter_by(hash=hash_value).first()
    
    def get_by_source_and_rule_id(self, source_id: int, rule_id: str) -> Optional[DetectionRule]:
        """Get rule by source and original rule ID"""
        return (
            self.session.query(DetectionRule)
            .filter_by(source_id=source_id, rule_id=rule_id)
            .first()
        )
    
    def get_with_enrichments(self, rule_id: int) -> Optional[DetectionRule]:
        """Get rule with all enrichment data loaded"""
        return (
            self.session.query(DetectionRule)
            .options(
                joinedload(DetectionRule.source),
                selectinload(DetectionRule.mitre_mappings).joinedload(RuleMitreMapping.technique),
                selectinload(DetectionRule.cve_mappings).joinedload(RuleCveMapping.cve),
                selectinload(DetectionRule.ioc_mappings),
                selectinload(DetectionRule.performance_metrics),
                selectinload(DetectionRule.category_mappings)
            )
            .filter(DetectionRule.id == rule_id)
            .first()
        )
    
    def search_rules(
        self,
        query: Optional[str] = None,
        rule_types: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        source_ids: Optional[List[int]] = None,
        tags: Optional[List[str]] = None,
        is_active: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
        platforms: Optional[List[str]] = None,
        rule_platforms: Optional[List[str]] = None,
        tactics: Optional[List[str]] = None,
        validation_status: Optional[List[str]] = None,
        sort_by: str = 'updated_date',
        sort_dir: str = 'desc',
        mitre_techniques: Optional[List[str]] = None,
        cve_ids: Optional[List[str]] = None,
    ) -> Tuple[List[DetectionRule], int]:
        """Advanced rule search with filters including enhanced MITRE and CVE filtering"""
        
        query_builder = self.session.query(DetectionRule).options(joinedload(DetectionRule.source)).distinct()
        
        # Text search - enhanced to include metadata
        if query:
            search_term = f'%{query}%'
            query_builder = query_builder.filter(
                or_(
                    DetectionRule.name.ilike(search_term),
                    DetectionRule.description.ilike(search_term),
                    DetectionRule.rule_id.ilike(search_term),
                    DetectionRule.rule_content.ilike(search_term),
                    # Search in extracted MITRE techniques and CVEs from metadata
                    DetectionRule.rule_metadata['extracted_mitre_techniques'].op('?|')(
                        [query.upper()] if query.upper().startswith('T') else []
                    ),
                    DetectionRule.rule_metadata['extracted_cve_ids'].op('?|')(
                        [query.upper()] if query.upper().startswith('CVE') else []
                    )
                )
            )
        
        # Categorical filters
        if rule_types:
            query_builder = query_builder.filter(DetectionRule.rule_type.in_(rule_types))
        
        if severities:
            query_builder = query_builder.filter(DetectionRule.severity.in_(severities))
        
        if source_ids:
            query_builder = query_builder.filter(DetectionRule.source_id.in_(source_ids))
        
        # Enhanced tag filtering - includes enriched tags
        if tags:
            for tag in tags:
                query_builder = query_builder.filter(DetectionRule.tags.contains([tag]))
        
        if is_active is not None:
            query_builder = query_builder.filter(DetectionRule.is_active == is_active)
        
        # Rule platform filtering
        if rule_platforms:
            query_builder = query_builder.filter(
                DetectionRule.rule_metadata['rule_platforms'].op('?|')(rule_platforms)
            )

        # MITRE technique filtering - enhanced to use both mappings and metadata
        if mitre_techniques:
            # Create a subquery for rules with specific MITRE technique mappings
            technique_subquery = (
                self.session.query(RuleMitreMapping.rule_id)
                .join(MitreTechnique)
                .filter(MitreTechnique.technique_id.in_(mitre_techniques))
                .subquery()
            )
            
            # Also check metadata for extracted techniques
            metadata_condition = DetectionRule.rule_metadata['extracted_mitre_techniques'].op('?|')(mitre_techniques)
            
            query_builder = query_builder.filter(
                or_(
                    DetectionRule.id.in_(technique_subquery),
                    metadata_condition
                )
            )

        # CVE filtering - enhanced to use both mappings and metadata
        if cve_ids:
            # Create a subquery for rules with specific CVE mappings
            cve_subquery = (
                self.session.query(RuleCveMapping.rule_id)
                .join(CveEntry)
                .filter(CveEntry.cve_id.in_(cve_ids))
                .subquery()
            )
            
            # Also check metadata for extracted CVEs
            metadata_condition = DetectionRule.rule_metadata['extracted_cve_ids'].op('?|')(cve_ids)
            
            query_builder = query_builder.filter(
                or_(
                    DetectionRule.id.in_(cve_subquery),
                    metadata_condition
                )
            )

        # Platform and tactic filtering via MITRE mappings
        if platforms or tactics:
            query_builder = query_builder.join(RuleMitreMapping).join(MitreTechnique)
            
            if platforms:
                # Use explicit cast to ensure proper array comparison
                query_builder = query_builder.filter(
                    MitreTechnique.platforms.op('&&')(func.cast(platforms, ARRAY(text)))
                )
            
            if tactics:
                query_builder = query_builder.join(MitreTactic).filter(MitreTactic.name.in_(tactics))
        
        # Validation status filtering
        if validation_status:
            query_builder = query_builder.filter(
                DetectionRule.rule_metadata['validation_status'].astext.in_(validation_status)
            )

        # Get total count before pagination
        total_count_query = query_builder.statement.with_only_columns(func.count(DetectionRule.id.distinct()))
        total_count = self.session.execute(total_count_query).scalar()
        
        # Apply sorting
        sort_column = getattr(DetectionRule, sort_by, DetectionRule.updated_date)
        sort_func = desc if sort_dir == 'desc' else asc
        query_builder = query_builder.order_by(sort_func(sort_column))
        
        # Apply pagination
        rules = query_builder.offset(offset).limit(limit).all()
        
        return rules, total_count
    
    def get_rules_by_mitre_technique(self, technique_id: str) -> List[DetectionRule]:
        """Get rules that detect a specific MITRE technique"""
        # Check both mappings and metadata
        mapping_rules = (
            self.session.query(DetectionRule)
            .join(RuleMitreMapping)
            .join(MitreTechnique)
            .filter(MitreTechnique.technique_id == technique_id)
            .filter(DetectionRule.is_active == True)
        )
        
        metadata_rules = (
            self.session.query(DetectionRule)
            .filter(DetectionRule.rule_metadata['extracted_mitre_techniques'].op('?')([technique_id]))
            .filter(DetectionRule.is_active == True)
        )
        
        # Union the results and remove duplicates
        all_rules = mapping_rules.union(metadata_rules).all()
        return all_rules
    
    def get_rules_by_cve(self, cve_id: str) -> List[DetectionRule]:
        """Get rules related to a specific CVE"""
        # Check both mappings and metadata
        mapping_rules = (
            self.session.query(DetectionRule)
            .join(RuleCveMapping)
            .join(CveEntry)
            .filter(CveEntry.cve_id == cve_id)
            .filter(DetectionRule.is_active == True)
        )
        
        metadata_rules = (
            self.session.query(DetectionRule)
            .filter(DetectionRule.rule_metadata['extracted_cve_ids'].op('?')([cve_id]))
            .filter(DetectionRule.is_active == True)
        )
        
        # Union the results and remove duplicates
        all_rules = mapping_rules.union(metadata_rules).all()
        return all_rules
    
    def get_rules_with_enrichment_stats(self) -> Dict[str, Any]:
        """Get statistics about rule enrichment coverage"""
        total_rules = self.session.query(func.count(DetectionRule.id)).scalar()
        
        # Rules with MITRE mappings
        rules_with_mitre_mappings = (
            self.session.query(func.count(DetectionRule.id.distinct()))
            .join(RuleMitreMapping)
            .scalar()
        )
        
        # Rules with MITRE data in metadata
        rules_with_mitre_metadata = (
            self.session.query(func.count(DetectionRule.id))
            .filter(DetectionRule.rule_metadata['extracted_mitre_techniques'].op('!=')('[]'))
            .scalar()
        )
        
        # Rules with CVE mappings
        rules_with_cve_mappings = (
            self.session.query(func.count(DetectionRule.id.distinct()))
            .join(RuleCveMapping)
            .scalar()
        )
        
        # Rules with CVE data in metadata
        rules_with_cve_metadata = (
            self.session.query(func.count(DetectionRule.id))
            .filter(DetectionRule.rule_metadata['extracted_cve_ids'].op('!=')('[]'))
            .scalar()
        )
        
        return {
            'total_rules': total_rules,
            'mitre_enrichment': {
                'with_mappings': rules_with_mitre_mappings,
                'with_metadata': rules_with_mitre_metadata,
                'coverage_percentage': round((rules_with_mitre_mappings / total_rules * 100), 2) if total_rules > 0 else 0
            },
            'cve_enrichment': {
                'with_mappings': rules_with_cve_mappings,
                'with_metadata': rules_with_cve_metadata,
                'coverage_percentage': round((rules_with_cve_mappings / total_rules * 100), 2) if total_rules > 0 else 0
            }
        }
    
    def get_rules_by_source_type(self, source_type: str) -> List[DetectionRule]:
        """Get rules by source type (trinity_cyber, elastic, etc.)"""
        return (
            self.session.query(DetectionRule)
            .filter(DetectionRule.rule_metadata['source_type'].astext == source_type)
            .filter(DetectionRule.is_active == True)
            .all()
        )
    
    def get_performance_summary(self, rule_id: int) -> Dict[str, Any]:
        """Get aggregated performance metrics for a rule"""
        metrics = (
            self.session.query(
                func.sum(RulePerformance.detection_count).label('total_detections'),
                func.sum(RulePerformance.false_positive_count).label('total_fps'),
                func.sum(RulePerformance.true_positive_count).label('total_tps'),
                func.max(RulePerformance.last_detection).label('last_detection')
            )
            .filter(RulePerformance.rule_id == rule_id)
            .first()
        )
        
        if metrics and metrics.total_detections:
            fp_rate = float(metrics.total_fps) / float(metrics.total_detections) if metrics.total_detections > 0 else 0
            return {
                'total_detections': metrics.total_detections or 0,
                'total_false_positives': metrics.total_fps or 0,
                'total_true_positives': metrics.total_tps or 0,
                'false_positive_rate': round(fp_rate, 4),
                'last_detection': metrics.last_detection
            }
        
        return {
            'total_detections': 0,
            'total_false_positives': 0,
            'total_true_positives': 0,
            'false_positive_rate': 0.0,
            'last_detection': None
        }