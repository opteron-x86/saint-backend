# enrichment_orchestrator.py
"""
SAINT Enrichment Orchestrator Lambda
Coordinates all enrichment processes for rules.

Triggers:
- Rule processor completion (event-driven)
- Scheduled runs (time-based) 
- Manual invocation (operational)
"""
import json
import logging
import boto3
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from saint_datamodel import db_session
from saint_datamodel.models import DetectionRule, RuleSource

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
lambda_client = boto3.client('lambda')

class EnrichmentOrchestrator:
    def __init__(self):
        self.rules_queued = 0 
        self.enrichment_tasks = []
        
    def orchestrate_enrichment(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main orchestration logic for enrichment processes.
        """
        # Determine enrichment scope based on event
        rule_filter = self._determine_enrichment_scope(event)
        
        # Get rules needing enrichment
        rules_to_enrich = self._get_rules_for_enrichment(rule_filter)
        
        if not rules_to_enrich:
            logger.info("No rules need enrichment")
            return {
                'statusCode': 200,
                'message': 'No rules need enrichment',
                'rules_processed': 0,
                'tasks_triggered': []
            }
        
        logger.info(f"Starting enrichment for {len(rules_to_enrich)} rules")
        
        # Trigger enrichment processes in parallel
        self._trigger_mitre_enrichment(rules_to_enrich)
        self._trigger_cve_enrichment(rules_to_enrich)
        # self._trigger_ioc_enrichment(rules_to_enrich)  # Optional
        
        return {
            'statusCode': 200,
            'message': f'Enrichment started for {len(rules_to_enrich)} rules',
            'rules_processed': len(rules_to_enrich),
            'tasks_triggered': self.enrichment_tasks,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _determine_enrichment_scope(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Determine what rules need enrichment based on the event.
        """
        if 'source_completed' in event:
            # Enrich specific source's rules (event-driven from rule processor)
            return {
                'type': 'source_rules',
                'source_id': event.get('source_id'),
                'rule_ids': event.get('rule_ids', [])
            }
        elif 'full_enrichment' in event:
            # Enrich all rules (maintenance run)
            return {'type': 'all_rules'}
            
        elif 'missing_enrichments' in event:
            # Default: enrich rules without enrichments
            return {'type': 'missing_enrichments'}
            
        elif 'rule_ids' in event:
            # Specific rule IDs provided
            return {
                'type': 'specific_rules',
                'rule_ids': event['rule_ids']
            }
        else:
            # Default behavior
            return {'type': 'missing_enrichments'}
    
    def _get_rules_for_enrichment(self, rule_filter: Dict[str, Any]) -> List[int]:
        """
        Get list of rule IDs that need enrichment based on filter criteria.
        """
        with db_session() as session:
            query = session.query(DetectionRule.id)
            
            if rule_filter['type'] == 'source_rules':
                # Rules from specific source
                if rule_filter.get('rule_ids'):
                    # Specific rule IDs provided
                    query = query.filter(DetectionRule.id.in_(rule_filter['rule_ids']))
                else:
                    # All rules from source
                    query = query.filter(DetectionRule.source_id == rule_filter['source_id'])
                    
            elif rule_filter['type'] == 'specific_rules':
                # Specific rule IDs
                query = query.filter(DetectionRule.id.in_(rule_filter['rule_ids']))
                
            elif rule_filter['type'] == 'missing_enrichments':
                # Rules that haven't been enriched yet
                query = query.filter(
                    DetectionRule.rule_metadata.is_(None)
                    | ~DetectionRule.rule_metadata.has_key('enrichment_completed')
                )
                
            elif rule_filter['type'] == 'all_rules':
                # All active rules
                query = query.filter(DetectionRule.is_active == True)
            
            # Limit to prevent overwhelming the system
            max_rules = rule_filter.get('max_rules', 1000)
            rule_ids = [row[0] for row in query.limit(max_rules).all()]
            
            logger.info(f"Found {len(rule_ids)} rules for enrichment (filter: {rule_filter['type']})")
            return rule_ids
    
    def _trigger_mitre_enrichment(self, rule_ids: List[int]):
        """Trigger MITRE enrichment Lambda."""
        try:
            payload = {
                'rule_ids': rule_ids,
                'orchestrator_id': f"mitre_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            }
            
            response = lambda_client.invoke(
                FunctionName='saint-mitre-enricher',
                InvocationType='Event',  # Async invocation
                Payload=json.dumps(payload)
            )
            
            self.enrichment_tasks.append('mitre_enrichment')
            logger.info(f"Triggered MITRE enrichment for {len(rule_ids)} rules")
            
        except Exception as e:
            logger.error(f"Failed to trigger MITRE enrichment: {e}")
            # Don't fail the entire orchestration
    
    def _trigger_cve_enrichment(self, rule_ids: List[int]):
        """Trigger CVE enrichment Lambda."""
        try:
            payload = {
                'rule_ids': rule_ids,
                'orchestrator_id': f"cve_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            }
            
            response = lambda_client.invoke(
                FunctionName='saint-cve-enricher',
                InvocationType='Event',  # Async invocation
                Payload=json.dumps(payload)
            )
            
            self.enrichment_tasks.append('cve_enrichment')
            logger.info(f"Triggered CVE enrichment for {len(rule_ids)} rules")
            
        except Exception as e:
            logger.error(f"Failed to trigger CVE enrichment: {e}")
            # Don't fail the entire orchestration
    
    def _trigger_ioc_enrichment(self, rule_ids: List[int]):
        """Trigger IOC enrichment Lambda (optional)."""
        try:
            payload = {
                'rule_ids': rule_ids,
                'orchestrator_id': f"ioc_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            }
            
            response = lambda_client.invoke(
                FunctionName='saint-ioc-enricher',
                InvocationType='Event',  # Async invocation
                Payload=json.dumps(payload)
            )
            
            self.enrichment_tasks.append('ioc_enrichment')
            logger.info(f"Triggered IOC enrichment for {len(rule_ids)} rules")
            
        except Exception as e:
            logger.error(f"Failed to trigger IOC enrichment: {e}")
            # Don't fail the entire orchestration

def lambda_handler(event, context):
    """
    Lambda entry point for enrichment orchestration.
    
    Event formats:
    - Rule processor completion: {"source_completed": true, "source_id": 14, "rule_ids": [1,2,3]}
    - Scheduled enrichment: {"missing_enrichments": true}
    - Full enrichment: {"full_enrichment": true}
    - Manual enrichment: {"rule_ids": [1,2,3]}
    """
    orchestrator = EnrichmentOrchestrator()
    
    try:
        result = orchestrator.orchestrate_enrichment(event)
        logger.info(f"Enrichment orchestration complete: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Enrichment orchestration failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e),
            'message': 'Enrichment orchestration failed'
        }