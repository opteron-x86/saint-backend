# api-handler/utils/deprecated_handler.py
"""
Service class for managing deprecated MITRE ATT&CK techniques in detection rules
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from saint_datamodel.models import MitreTechnique, DetectionRule, RuleMitreMapping

logger = logging.getLogger(__name__)


class DeprecatedTechniqueHandler:
    """Handles deprecated technique detection and recommendations"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def check_rule_for_deprecated_techniques(self, rule_id: int) -> List[Dict[str, Any]]:
        """
        Check if a rule has mappings to deprecated techniques.
        Returns a list of warnings for deprecated techniques.
        """
        warnings = []
        
        # Get all technique mappings for the rule
        mappings = (
            self.session.query(RuleMitreMapping)
            .filter_by(rule_id=rule_id)
            .join(MitreTechnique)
            .all()
        )
        
        for mapping in mappings:
            technique = mapping.technique
            
            if technique.is_deprecated or technique.revoked:
                warning = {
                    'technique_id': technique.technique_id,
                    'technique_name': technique.name,
                    'deprecated_date': technique.deprecated_date.isoformat() if technique.deprecated_date else None,
                    'superseded_by': technique.superseded_by,
                    'deprecation_reason': technique.deprecation_reason,
                    'is_revoked': technique.revoked,
                    'mapping_confidence': float(mapping.mapping_confidence),
                    'recommendation': self._generate_recommendation(technique)
                }
                warnings.append(warning)
                
                # Log the warning
                logger.warning(
                    f"Rule {rule_id} is mapped to {'revoked' if technique.revoked else 'deprecated'} "
                    f"technique {technique.technique_id} ({technique.name})"
                )
        
        return warnings
    
    def _generate_recommendation(self, technique: MitreTechnique) -> str:
        """Generate a recommendation for handling a deprecated technique"""
        if technique.revoked:
            action = "remove this technique mapping as it has been revoked"
        else:
            action = "review this deprecated technique mapping"
        
        if technique.superseded_by:
            # Look up the superseding technique
            superseding = (
                self.session.query(MitreTechnique)
                .filter_by(technique_id=technique.superseded_by)
                .first()
            )
            
            if superseding:
                return f"Recommended: {action} and consider mapping to {technique.superseded_by} ({superseding.name}) instead"
            else:
                return f"Recommended: {action} and consider mapping to {technique.superseded_by} instead"
        else:
            return f"Recommended: {action} - no direct replacement available"
    
    def find_rules_with_deprecated_techniques(self) -> List[Dict[str, Any]]:
        """
        Find all rules that have mappings to deprecated techniques.
        """
        deprecated_mappings = (
            self.session.query(
                DetectionRule.id,
                DetectionRule.rule_id,
                DetectionRule.name,
                DetectionRule.rule_source,
                MitreTechnique.technique_id,
                MitreTechnique.name.label('technique_name'),
                MitreTechnique.is_deprecated,
                MitreTechnique.revoked,
                MitreTechnique.superseded_by,
                RuleMitreMapping.mapping_confidence
            )
            .join(RuleMitreMapping, DetectionRule.id == RuleMitreMapping.rule_id)
            .join(MitreTechnique, RuleMitreMapping.technique_id == MitreTechnique.id)
            .filter((MitreTechnique.is_deprecated == True) | (MitreTechnique.revoked == True))
            .all()
        )
        
        results = []
        for mapping in deprecated_mappings:
            results.append({
                'rule_id': mapping.id,
                'source_rule_id': mapping.rule_id,
                'rule_name': mapping.name,
                'rule_source': mapping.rule_source,
                'deprecated_technique_id': mapping.technique_id,
                'deprecated_technique_name': mapping.technique_name,
                'is_deprecated': mapping.is_deprecated,
                'is_revoked': mapping.revoked,
                'superseded_by': mapping.superseded_by,
                'mapping_confidence': float(mapping.mapping_confidence) if mapping.mapping_confidence else None
            })
        
        return results
    
    def get_deprecation_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about deprecated techniques in the system.
        """
        total_techniques = self.session.query(MitreTechnique).count()
        deprecated_techniques = (
            self.session.query(MitreTechnique)
            .filter(MitreTechnique.is_deprecated == True)
            .count()
        )
        revoked_techniques = (
            self.session.query(MitreTechnique)
            .filter(MitreTechnique.revoked == True)
            .count()
        )
        
        # Count techniques with replacements
        techniques_with_replacements = (
            self.session.query(MitreTechnique)
            .filter(
                (MitreTechnique.is_deprecated == True) | (MitreTechnique.revoked == True),
                MitreTechnique.superseded_by.isnot(None)
            )
            .count()
        )
        
        # Count rules affected
        rules_with_deprecated = (
            self.session.query(DetectionRule.id)
            .join(RuleMitreMapping, DetectionRule.id == RuleMitreMapping.rule_id)
            .join(MitreTechnique, RuleMitreMapping.technique_id == MitreTechnique.id)
            .filter((MitreTechnique.is_deprecated == True) | (MitreTechnique.revoked == True))
            .distinct()
            .count()
        )
        
        return {
            'total_techniques': total_techniques,
            'deprecated_techniques': deprecated_techniques,
            'revoked_techniques': revoked_techniques,
            'total_deprecated_or_revoked': deprecated_techniques + revoked_techniques,
            'techniques_with_replacements': techniques_with_replacements,
            'rules_affected': rules_with_deprecated,
            'percentage_deprecated': round((deprecated_techniques / total_techniques * 100), 2) if total_techniques > 0 else 0,
            'percentage_revoked': round((revoked_techniques / total_techniques * 100), 2) if total_techniques > 0 else 0
        }
    
    def update_deprecated_mappings(self, auto_update: bool = False) -> Dict[str, Any]:
        """
        Update mappings from deprecated techniques to their replacements.
        
        Args:
            auto_update: If True, automatically update mappings where a clear replacement exists.
                        If False, only generate recommendations.
        
        Returns:
            Summary of updates or recommendations.
        """
        updates = []
        recommendations = []
        
        # Find all mappings to deprecated techniques with replacements
        deprecated_mappings = (
            self.session.query(RuleMitreMapping)
            .join(MitreTechnique)
            .filter(
                (MitreTechnique.is_deprecated == True) | (MitreTechnique.revoked == True),
                MitreTechnique.superseded_by.isnot(None)
            )
            .all()
        )
        
        for mapping in deprecated_mappings:
            old_technique = mapping.technique
            
            # Find the replacement technique
            new_technique = (
                self.session.query(MitreTechnique)
                .filter_by(technique_id=old_technique.superseded_by)
                .first()
            )
            
            if new_technique:
                if auto_update:
                    # Check if mapping already exists
                    existing_mapping = (
                        self.session.query(RuleMitreMapping)
                        .filter_by(
                            rule_id=mapping.rule_id,
                            technique_id=new_technique.id
                        )
                        .first()
                    )
                    
                    if not existing_mapping:
                        # Update the mapping
                        mapping.technique_id = new_technique.id
                        updates.append({
                            'rule_id': mapping.rule_id,
                            'old_technique': old_technique.technique_id,
                            'new_technique': new_technique.technique_id
                        })
                        logger.info(
                            f"Updated mapping for rule {mapping.rule_id}: "
                            f"{old_technique.technique_id} -> {new_technique.technique_id}"
                        )
                    else:
                        # Mapping already exists, remove the deprecated one
                        self.session.delete(mapping)
                        updates.append({
                            'rule_id': mapping.rule_id,
                            'old_technique': old_technique.technique_id,
                            'action': 'removed_duplicate'
                        })
                else:
                    recommendations.append({
                        'rule_id': mapping.rule_id,
                        'current_technique': old_technique.technique_id,
                        'recommended_technique': new_technique.technique_id,
                        'reason': old_technique.deprecation_reason or 'Technique deprecated'
                    })
        
        if auto_update:
            self.session.commit()
        
        return {
            'updates_made': len(updates),
            'recommendations_generated': len(recommendations),
            'updates': updates if auto_update else [],
            'recommendations': recommendations if not auto_update else []
        }