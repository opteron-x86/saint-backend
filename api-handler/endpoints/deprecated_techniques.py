# endpoints/deprecated_techniques.py
"""
API endpoints for managing deprecated MITRE techniques
"""

import logging
from typing import Dict, Any

from saint_datamodel import db_session
from api_utils.response_helpers import create_api_response, create_error_response, create_success_response
from api_utils.deprecated_handler import DeprecatedTechniqueHandler

logger = logging.getLogger(__name__)


def get_deprecated_statistics(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get statistics about deprecated techniques in the system"""
    try:
        with db_session() as session:
            handler = DeprecatedTechniqueHandler(session)
            stats = handler.get_deprecation_statistics()
            
            # Use create_success_response or create_api_response with positional args
            return create_success_response(stats, "Deprecated technique statistics retrieved successfully")
    except Exception as e:
        logger.error(f"Error getting deprecated statistics: {e}")
        return create_error_response(500, str(e))


def get_rules_with_deprecated_techniques(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get all rules that have mappings to deprecated techniques"""
    try:
        with db_session() as session:
            handler = DeprecatedTechniqueHandler(session)
            affected_rules = handler.find_rules_with_deprecated_techniques()
            
            # Group by rule for better organization
            rules_by_id = {}
            for mapping in affected_rules:
                rule_id = mapping['rule_id']
                if rule_id not in rules_by_id:
                    rules_by_id[rule_id] = {
                        'rule_id': rule_id,
                        'source_rule_id': mapping['source_rule_id'],
                        'rule_name': mapping['rule_name'],
                        'rule_source': mapping['rule_source'],
                        'deprecated_techniques': []
                    }
                
                rules_by_id[rule_id]['deprecated_techniques'].append({
                    'technique_id': mapping['deprecated_technique_id'],
                    'technique_name': mapping['deprecated_technique_name'],
                    'is_deprecated': mapping['is_deprecated'],
                    'is_revoked': mapping['is_revoked'],
                    'superseded_by': mapping['superseded_by'],
                    'mapping_confidence': mapping['mapping_confidence']
                })
            
            response_data = {
                'total_affected_rules': len(rules_by_id),
                'rules': list(rules_by_id.values())
            }
            
            return create_success_response(
                response_data, 
                f"Found {len(rules_by_id)} rules with deprecated techniques"
            )
    except Exception as e:
        logger.error(f"Error finding rules with deprecated techniques: {e}")
        return create_error_response(500, str(e))


def check_rule_deprecated_techniques(params: Dict[str, Any]) -> Dict[str, Any]:
    """Check a specific rule for deprecated technique mappings"""
    try:
        rule_id = params.get('rule_id')
        if not rule_id:
            return create_error_response(400, "rule_id is required")
        
        with db_session() as session:
            handler = DeprecatedTechniqueHandler(session)
            warnings = handler.check_rule_for_deprecated_techniques(int(rule_id))
            
            response_data = {
                'rule_id': rule_id,
                'has_deprecated_techniques': len(warnings) > 0,
                'deprecated_count': len(warnings),
                'warnings': warnings
            }
            
            return create_success_response(
                response_data,
                "Rule checked for deprecated techniques"
            )
    except ValueError as e:
        return create_error_response(400, f"Invalid rule_id: {e}")
    except Exception as e:
        logger.error(f"Error checking rule {params.get('rule_id')} for deprecated techniques: {e}")
        return create_error_response(500, str(e))


def update_deprecated_mappings(params: Dict[str, Any]) -> Dict[str, Any]:
    """Generate recommendations or auto-update deprecated technique mappings"""
    try:
        auto_update = params.get('auto_update', False)
        
        with db_session() as session:
            handler = DeprecatedTechniqueHandler(session)
            result = handler.update_deprecated_mappings(auto_update=auto_update)
            
            action = "updated" if auto_update else "analyzed"
            
            return create_success_response(
                result,
                f"Deprecated technique mappings {action} successfully"
            )
    except Exception as e:
        logger.error(f"Error updating deprecated mappings: {e}")
        return create_error_response(500, str(e))


# Lambda handler routing
def lambda_handler(event, context):
    """Route requests to appropriate handlers"""
    path = event.get('path', '')
    method = event.get('httpMethod', 'GET')
    params = event.get('queryStringParameters', {}) or {}
    
    # Add body parameters for POST requests
    if method == 'POST' and event.get('body'):
        import json
        try:
            body_params = json.loads(event['body'])
            params.update(body_params)
        except json.JSONDecodeError:
            pass
    
    # Route to appropriate handler
    if path.endswith('/deprecated/statistics'):
        return get_deprecated_statistics(params)
    elif path.endswith('/deprecated/affected-rules'):
        return get_rules_with_deprecated_techniques(params)
    elif path.endswith('/deprecated/check-rule'):
        return check_rule_deprecated_techniques(params)
    elif path.endswith('/deprecated/update-mappings'):
        return update_deprecated_mappings(params)
    else:
        return create_error_response(404, f"Unknown endpoint: {path}")