"""
Repository for MITRE ATT&CK data
Fixed version that avoids PostgreSQL-specific SQLAlchemy functions
"""

from typing import List, Optional, Dict, Any
import json

from sqlalchemy import and_, func, cast, TEXT, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Session

from .base import BaseRepository
from ..models.mitre import MitreTactic, MitreTechnique, MitreGroup, MitreSoftware
from ..models.rules import DetectionRule
from ..models.relationships import RuleMitreMapping

class MitreRepository(BaseRepository[MitreTechnique]):
    """Repository for MITRE ATT&CK data"""
    
    def __init__(self, session: Session):
        super().__init__(session, MitreTechnique)
    
    def get_technique_by_id(self, technique_id: str) -> Optional[MitreTechnique]:
        """Get technique by MITRE technique ID"""
        return (
            self.session.query(MitreTechnique)
            .filter_by(technique_id=technique_id)
            .first()
        )
    
    def get_techniques_by_tactic(self, tactic_id: str) -> List[MitreTechnique]:
        """Get techniques for a specific tactic"""
        return (
            self.session.query(MitreTechnique)
            .join(MitreTactic)
            .filter(MitreTactic.tactic_id == tactic_id)
            .all()
        )
    
    def get_coverage_analysis(self, platforms: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get rule coverage analysis for MITRE techniques.
        Simplified version that avoids PostgreSQL-specific functions.
        """
        # Base query with left join to get all techniques even without rules
        query = (
            self.session.query(
                MitreTechnique.technique_id,
                MitreTechnique.name,
                func.count(DetectionRule.id).label('rule_count')
            )
            .select_from(MitreTechnique)
            .outerjoin(RuleMitreMapping, MitreTechnique.id == RuleMitreMapping.technique_id)
            .outerjoin(DetectionRule, and_(
                RuleMitreMapping.rule_id == DetectionRule.id,
                DetectionRule.is_active == True
            ))
        )

        # Apply platform filter if provided
        if platforms:
            # Use text() for raw SQL to avoid import issues
            platform_filter = text("mitre_techniques.platforms && :platforms")
            query = query.filter(platform_filter).params(platforms=platforms)

        # Group and order results
        results = (
            query
            .group_by(MitreTechnique.id, MitreTechnique.technique_id, MitreTechnique.name)
            .order_by(MitreTechnique.technique_id)
            .all()
        )
        
        # Build the response with rule details
        coverage_data = []
        for r in results:
            # Get rule details for this technique separately to avoid complex aggregation
            rules_for_technique = []
            if r.rule_count > 0:
                rule_details = (
                    self.session.query(
                        DetectionRule.id,
                        DetectionRule.name,
                        DetectionRule.severity
                    )
                    .join(RuleMitreMapping, DetectionRule.id == RuleMitreMapping.rule_id)
                    .join(MitreTechnique, RuleMitreMapping.technique_id == MitreTechnique.id)
                    .filter(MitreTechnique.technique_id == r.technique_id)
                    .filter(DetectionRule.is_active == True)
                    .order_by(DetectionRule.severity)
                    .all()
                )
                
                rules_for_technique = [
                    {
                        'id': rule.id,
                        'title': rule.name,
                        'severity': rule.severity
                    }
                    for rule in rule_details
                ]
            
            coverage_data.append({
                'technique_id': r.technique_id,
                'name': r.name,
                'count': r.rule_count,
                'rules': rules_for_technique
            })
        
        return coverage_data
    
    def get_tactic_by_id(self, tactic_id: str) -> Optional[MitreTactic]:
        """Get tactic by MITRE tactic ID"""
        return (
            self.session.query(MitreTactic)
            .filter_by(tactic_id=tactic_id)
            .first()
        )
    
    def get_group_by_id(self, group_id: str) -> Optional[MitreGroup]:
        """Get group by MITRE group ID"""
        return (
            self.session.query(MitreGroup)
            .filter_by(group_id=group_id)
            .first()
        )
    
    def get_software_by_id(self, software_id: str) -> Optional[MitreSoftware]:
        """Get software by MITRE software ID"""
        return (
            self.session.query(MitreSoftware)
            .filter_by(software_id=software_id)
            .first()
        )