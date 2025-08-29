# lambda_function.py

import json
import logging
import re
import os
from typing import Dict, Any, List, Optional
from functools import wraps

# JWT imports for Cognito validation
try:
    import jwt
    from jwt import PyJWKClient
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    logging.warning("PyJWT not available - auth validation disabled")

# Import from the saint-datamodel layer
from saint_datamodel import db_session
from saint_datamodel.exceptions import NotFoundError, ValidationError, DatabaseError

# Import local modules
from api_utils.response_helpers import create_api_response, create_error_response
from endpoints import rules, mitre, cve, filters, statistics, issues, deprecated_techniques

# --- Logging Setup ---
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- Cognito Configuration ---
COGNITO_REGION = os.environ.get('COGNITO_REGION', '')
COGNITO_USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID', '')
COGNITO_CLIENT_ID = os.environ.get('COGNITO_CLIENT_ID', '')
DISABLE_AUTH = os.environ.get('DISABLE_AUTH', 'false').lower() == 'true'

# Initialize JWT client if available and auth enabled
jwks_client = None
if JWT_AVAILABLE and not DISABLE_AUTH:
    jwks_url = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    jwks_client = PyJWKClient(jwks_url)

def validate_jwt_token(token: str) -> Dict[str, Any]:
    """Validate Cognito JWT token"""
    if not JWT_AVAILABLE:
        raise ValidationError("JWT validation not available")
    
    try:
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]
        
        # Get the signing key from Cognito
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        # Decode and validate the token
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
            issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}",
            options={"verify_exp": True}
        )
        
        return decoded
    except jwt.ExpiredSignatureError:
        raise ValidationError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise ValidationError(f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        raise ValidationError("Token validation failed")

def extract_user_context(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract and validate user context from request"""
    if DISABLE_AUTH:
        logger.info("Auth disabled - using dev context")
        return {"sub": "local-dev", "email": "dev@local"}
    
    # First check if API Gateway already validated (Cognito Authorizer)
    request_context = event.get('requestContext', {})
    authorizer = request_context.get('authorizer', {})
    if authorizer.get('claims'):
        logger.info("Using API Gateway authorizer claims")
        return authorizer['claims']
    
    # Otherwise validate token ourselves
    headers = event.get('headers', {})
    auth_header = headers.get('Authorization') or headers.get('authorization')
    
    if not auth_header:
        logger.warning("No authorization header found")
        return None
    
    try:
        user_claims = validate_jwt_token(auth_header)
        logger.info(f"Token validated for user: {user_claims.get('email', 'unknown')}")
        return user_claims
    except ValidationError as e:
        logger.error(f"Token validation failed: {e}")
        return None

def add_cors_headers(response: Dict[str, Any]) -> Dict[str, Any]:
    """Add comprehensive CORS headers to response"""
    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": True,
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
        "Access-Control-Max-Age": "86400",
        "Content-Type": "application/json"
    }
    
    if "headers" in response:
        response["headers"].update(cors_headers)
    else:
        response["headers"] = cors_headers
    
    return response

def parse_query_parameters(event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse and normalize query parameters from API Gateway event"""
    params = event.get('queryStringParameters') or {}
    multi_params = event.get('multiValueQueryStringParameters') or {}
    
    # Handle multi-value parameters
    for key, value_list in multi_params.items():
        if key in ['query', 'offset', 'limit', 'sort_by', 'sort_dir']:
            params[key] = value_list[0] if value_list else None
        else:
            params[key] = value_list
    
    # Convert string numbers to integers
    for key in ['offset', 'limit']:
        if key in params and params[key] is not None:
            try:
                params[key] = int(params[key])
            except (ValueError, TypeError):
                params[key] = 0 if key == 'offset' else 100
    
    # Set defaults
    params.setdefault('offset', 0)
    params.setdefault('limit', 100)
    
    # Validate bounds
    if params['limit'] > 1000:
        params['limit'] = 1000
    elif params['limit'] < 1:
        params['limit'] = 1
        
    return params

def validate_path_parameters(path_params: Dict[str, str]) -> Dict[str, str]:
    """Validate and sanitize path parameters"""
    validated = {}
    
    for key, value in path_params.items():
        if key == 'rule_id':
            if re.match(r'^[a-zA-Z0-9\-_\.]{1,255}$', value):
                validated[key] = value
            else:
                raise ValidationError(f"Invalid rule_id format: {value}")
        elif key == 'cve_id':
            if re.match(r'^CVE-\d{4}-\d{4,}$', value, re.IGNORECASE):
                validated[key] = value.upper()
            else:
                raise ValidationError(f"Invalid CVE ID format: {value}")
        else:
            validated[key] = str(value)[:255]
    
    return validated

def handle_options_request() -> Dict[str, Any]:
    """Handle CORS preflight requests"""
    return add_cors_headers({
        "statusCode": 200,
        "body": json.dumps({"message": "CORS preflight"})
    })

def handle_global_search(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle global search across rules, techniques, and CVEs"""
    query = params.get('query', '').strip()
    if not query:
        return create_error_response(400, "Query parameter required")
    
    try:
        with db_session() as session:
            results = {
                'rules': [],
                'techniques': [],
                'cves': []
            }
            
            # Search rules
            rule_results = rules.search_rules({
                'query': query,
                'limit': 10
            })
            if rule_results.get('statusCode') == 200:
                data = json.loads(rule_results['body'])
                results['rules'] = data.get('data', [])[:5]
            
            # Search techniques
            technique_results = mitre.get_techniques_list({
                'query': query,
                'limit': 10
            })
            if technique_results.get('statusCode') == 200:
                data = json.loads(technique_results['body'])
                results['techniques'] = data.get('data', [])[:5]
            
            # Search CVEs
            cve_results = cve.search_cves({
                'query': query,
                'limit': 10
            })
            if cve_results.get('statusCode') == 200:
                data = json.loads(cve_results['body'])
                results['cves'] = data.get('data', [])[:5]
            
            return create_api_response(200, results)
        
    except Exception as e:
        logger.error(f"Error in global search: {e}", exc_info=True)
        return create_error_response(500, "Search failed")

def route_request(http_method: str, path: str, params: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    """Route incoming requests to appropriate endpoint handlers"""
    
    normalized_path = path.rstrip('/')
    path_params = event.get('pathParameters') or {}
    
    try:
        # Validate path parameters
        validated_path_params = validate_path_parameters(path_params)
        
        # Health Check (public)
        if http_method == 'GET' and normalized_path in ['/health', '']:
            return create_api_response(200, {
                "status": "healthy", 
                "service": "saint-api",
                "version": "2.0",
                "auth_enabled": not DISABLE_AUTH
            })

        # API Documentation (public)
        if http_method == 'GET' and normalized_path == '/api/docs':
            return create_api_response(200, {
                "title": "SAINT API Documentation",
                "version": "2.0",
                "auth_required": not DISABLE_AUTH,
                "endpoints": {
                    "rules": "GET /rules - Search detection rules",
                    "rule_details": "GET /rules/{id} - Get rule details",
                    "rule_stats": "GET /rules/stats - Get statistics",
                    "mitre_matrix": "GET /mitre/matrix - Get MITRE matrix",
                    "mitre_coverage": "GET /mitre/coverage - Get coverage",
                    "cves": "GET /cves - Search CVEs",
                    "filters": "GET /filters/options - Get filter options",
                    "deprecated": {
                        "statistics": "GET /deprecated/statistics - Deprecation metrics",
                        "affected_rules": "GET /deprecated/affected-rules - List affected rules",
                        "check_rule": "GET /deprecated/check-rule - Check specific rule",
                        "update_mappings": "POST /deprecated/update-mappings - Update mappings"
                    }
                }
            })

        # --- Protected Endpoints Below ---
        
        # Rules endpoints
        if http_method == 'GET' and normalized_path == '/rules':
            return rules.search_rules(params)
        
        if http_method == 'GET' and normalized_path == '/rules/stats':
            return statistics.handle_get_stats(params)
        
        if http_method == 'GET' and normalized_path == '/rules/enrichment':
            return rules.get_enrichment_stats(params)
        
        if http_method == 'GET' and normalized_path == '/rules/export':
            return rules.export_rules(params)
        
        if http_method == 'GET' and re.match(r'^/rules/[^/]+$', normalized_path):
            return rules.get_rule_details(validated_path_params['rule_id'])
        
        if http_method == 'POST' and re.match(r'^/rules/[^/]+/issues$', normalized_path):
            body = json.loads(event.get('body', '{}'))
            return issues.create_rule_issue(validated_path_params['rule_id'], body, params.get('user_context'))
        
        # MITRE endpoints
        if http_method == 'GET' and normalized_path == '/mitre/matrix':
            return mitre.get_mitre_matrix(params)
        
        if http_method == 'GET' and normalized_path == '/mitre/coverage':
            return mitre.get_coverage_analysis(params)
        
        if http_method == 'GET' and normalized_path == '/mitre/techniques':
            return mitre.get_techniques_list(params)
        
        if http_method == 'GET' and normalized_path == '/mitre/tactics':
            return mitre.get_tactics_list(params)
        
        # CVE endpoints
        if http_method == 'GET' and normalized_path == '/cves':
            return cve.search_cves(params)
        
        if http_method == 'GET' and normalized_path == '/cves/stats':
            return cve.get_cve_stats(params)
        
        if http_method == 'GET' and re.match(r'^/cves/CVE-\d{4}-\d+$', normalized_path):
            return cve.get_cve_details(validated_path_params['cve_id'])
        
        # Filter endpoints
        if http_method == 'GET' and normalized_path == '/filters/options':
            return filters.get_filter_options()
        
        # Analytics endpoints
        if http_method == 'GET' and normalized_path == '/analytics/dashboard':
            return statistics.get_dashboard_data(params)
        
        if http_method == 'GET' and normalized_path == '/analytics/trends':
            return statistics.get_trend_analysis(params)
        
        # Deprecated techniques endpoints
        if http_method == 'GET' and normalized_path == '/deprecated/statistics':
            return deprecated_techniques.get_deprecated_statistics(params)
        
        if http_method == 'GET' and normalized_path == '/deprecated/affected-rules':
            return deprecated_techniques.get_rules_with_deprecated_techniques(params)
        
        if http_method == 'GET' and normalized_path == '/deprecated/check-rule':
            # Can accept rule_id from query params or path params
            if 'rule_id' not in params and 'rule_id' in validated_path_params:
                params['rule_id'] = validated_path_params['rule_id']
            return deprecated_techniques.check_rule_deprecated_techniques(params)
        
        if http_method == 'POST' and normalized_path == '/deprecated/update-mappings':
            # Parse body for POST request
            body = json.loads(event.get('body', '{}'))
            return deprecated_techniques.update_deprecated_mappings(body)
        
        # Global search
        if http_method == 'GET' and normalized_path == '/search':
            return handle_global_search(params)
        
        # No matching route
        return create_error_response(404, f"Endpoint not found: {http_method} {path}")
        
    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return create_error_response(400, str(e))
    except NotFoundError as e:
        logger.warning(f"Resource not found: {e}")
        return create_error_response(404, str(e))
    except DatabaseError as e:
        logger.error(f"Database error: {e}", exc_info=True)
        return create_error_response(503, "Database temporarily unavailable")
    except Exception as e:
        logger.error(f"Unexpected error in routing: {e}", exc_info=True)
        return create_error_response(500, "Internal server error")

def lambda_handler(event: Dict[str, Any], context: object) -> Dict[str, Any]:
    """Main Lambda handler with Cognito authentication"""
    
    logger.info(f"Request: {event.get('httpMethod')} {event.get('path')}")
    
    # Parse request
    http_method = event.get('httpMethod', '').upper()
    path = event.get('path', '/')
    params = parse_query_parameters(event)
    
    # Handle CORS preflight
    if http_method == 'OPTIONS':
        return handle_options_request()
    
    # Public endpoints that don't require auth
    public_endpoints = ['/health', '/api/docs', '/']
    is_public = any(path.rstrip('/') == ep or path.startswith(ep) for ep in public_endpoints)
    
    # Validate authentication for protected endpoints
    user_context = None
    if not is_public:
        user_context = extract_user_context(event)
        if not user_context and not DISABLE_AUTH:
            logger.warning(f"Unauthorized access attempt to {path}")
            return add_cors_headers({
                "statusCode": 401,
                "body": json.dumps({"error": "Unauthorized - valid JWT token required"})
            })
    
    # Add user context to params for downstream use
    if user_context:
        params['user_context'] = user_context
        logger.info(f"Authenticated user: {user_context.get('email', 'unknown')}")
    
    try:
        # Route to endpoints
        response = route_request(http_method, path, params, event)
        return add_cors_headers(response)
    except Exception as e:
        logger.error(f"Request error: {e}", exc_info=True)
        return add_cors_headers(create_error_response(500, "Internal server error"))