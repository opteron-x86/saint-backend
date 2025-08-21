# crowdstrike_downloader.py
"""
Lambda function to download the latest ruleset from CrowdStrike API
and save it to an S3 bucket for processing.
"""
import os
import json
import logging
import requests
import boto3
from datetime import datetime, timezone
from zipfile import ZipFile, BadZipFile
from io import BytesIO
from requests.auth import HTTPBasicAuth

# --- Logging Setup ---
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- Configuration ---
CS_OAUTH_URL = "https://api.crowdstrike.com/oauth2/token"
CS_API_BASE_URL = "https://api.crowdstrike.com/intel/entities/rules-latest-files/v1"
DESTINATION_S3_BUCKET_ENV = os.environ.get('DESTINATION_S3_BUCKET')
CS_API_SECRET_ARN = os.environ.get('CS_API_SECRET_ARN')
CS_RULE_TYPES = os.environ.get('CS_RULE_TYPES', 'yara,snorticata')  # Support multiple types
USER_AGENT = "SAINT-Data-Processor/1.0"

s3_client = boto3.client('s3')
secrets_client = boto3.client('secretsmanager')

def get_api_credentials() -> tuple[str, str]:
    """Retrieves the CrowdStrike API credentials from AWS Secrets Manager."""
    if not CS_API_SECRET_ARN:
        raise ValueError("CS_API_SECRET_ARN environment variable not set.")
    try:
        response = secrets_client.get_secret_value(SecretId=CS_API_SECRET_ARN)
        secret = json.loads(response['SecretString'])
        return secret['client_id'], secret['client_secret']
    except Exception as e:
        logger.error(f"Failed to retrieve API credentials from Secrets Manager: {e}")
        raise

def get_oauth2_token(client_id: str, client_secret: str) -> str:
    """Fetch OAuth2 token using client credentials."""
    try:
        response = requests.post(
            CS_OAUTH_URL,
            auth=HTTPBasicAuth(client_id, client_secret),
            data={'grant_type': 'client_credentials'},
            timeout=30
        )
        response.raise_for_status()
        token_data = response.json()
        return token_data.get('access_token')
    except Exception as e:
        logger.error(f"Failed to obtain OAuth2 token: {e}")
        raise

def normalize_rule_type(rule_type: str) -> str:
    """Convert rule type to CrowdStrike API format."""
    if rule_type.lower() == 'yara':
        return 'yara-master'
    elif rule_type.lower() in ['snorticata', 'snort', 'suricata']:
        return 'snort-suricata-master'
    else:
        raise ValueError(f"Invalid rule type: {rule_type}. Must be 'yara' or 'snorticata'")

def download_ruleset(access_token: str, rule_type: str) -> bytes:
    """Download the CrowdStrike ruleset ZIP file."""
    normalized_type = normalize_rule_type(rule_type)
    api_url = f"{CS_API_BASE_URL}?type={normalized_type}"
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'User-Agent': USER_AGENT
    }
    
    logger.info(f"Downloading CrowdStrike ruleset: {normalized_type}")
    
    try:
        response = requests.get(api_url, headers=headers, timeout=120)
        response.raise_for_status()
        
        if len(response.content) == 0:
            raise ValueError("Received empty response from CrowdStrike API")
            
        return response.content
    except Exception as e:
        logger.error(f"Failed to download ruleset from CrowdStrike: {e}")
        raise

def extract_rules_from_zip(zip_content: bytes, rule_type: str) -> str:
    """Extract and combine rule files from ZIP content."""
    # Determine file extension based on rule type
    if rule_type.lower() == 'yara':
        file_extension = '.yara'
        rule_separator = "\n\n"  # YARA rules need more spacing
    else:  # snorticata
        file_extension = '.rules'
        rule_separator = "\n"   # Snort rules are line-based
    
    combined_rules = ""
    files_processed = 0
    
    try:
        with ZipFile(BytesIO(zip_content)) as zip_file:
            logger.info(f"ZIP contains files: {zip_file.namelist()}")
            
            for file_name in zip_file.namelist():
                if file_name.endswith(file_extension):
                    try:
                        with zip_file.open(file_name) as rule_file:
                            file_content = rule_file.read().decode('utf-8')
                            
                            # Add file header for better tracking
                            combined_rules += f"// Source file: {file_name}\n"
                            if rule_type.lower() == 'yara':
                                combined_rules += f"// Extracted: {datetime.now(timezone.utc).isoformat()}\n"
                            
                            combined_rules += file_content + rule_separator
                            files_processed += 1
                            
                            logger.info(f"Processed file: {file_name} ({len(file_content)} chars)")
                            
                    except UnicodeDecodeError as e:
                        logger.warning(f"Could not decode file {file_name} as UTF-8: {e}")
                        continue
                    except Exception as e:
                        logger.warning(f"Error processing file {file_name}: {e}")
                        continue
                        
        logger.info(f"Successfully extracted {files_processed} {file_extension} files from ZIP")
        
        if files_processed == 0:
            available_extensions = set(f.split('.')[-1] for f in zip_file.namelist() if '.' in f)
            raise ValueError(f"No {file_extension} files found in ZIP. Available extensions: {available_extensions}")
            
        return combined_rules.strip()
        
    except BadZipFile as e:
        logger.error(f"Downloaded content is not a valid ZIP file: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to extract rules from ZIP: {e}")
        raise

def lambda_handler(event, context):
    """Main handler to fetch CrowdStrike rules for all configured types and upload to S3."""
    if not DESTINATION_S3_BUCKET_ENV:
        logger.error("DESTINATION_S3_BUCKET environment variable is not set.")
        return {'statusCode': 500, 'body': json.dumps({'error': 'Configuration error.'})}

    try:
        # Parse bucket name from environment variable (handle ARN or name)
        bucket_name = DESTINATION_S3_BUCKET_ENV
        if bucket_name.startswith('arn:'):
            bucket_name = bucket_name.split(':')[-1]

        # Parse rule types from environment variable
        rule_types = [rt.strip() for rt in CS_RULE_TYPES.split(',')]
        logger.info(f"Processing rule types: {rule_types}")
        
        # Get API credentials and obtain access token
        client_id, client_secret = get_api_credentials()
        access_token = get_oauth2_token(client_id, client_secret)
        
        results = []
        
        # Process each rule type
        for rule_type in rule_types:
            try:
                logger.info(f"Processing rule type: {rule_type}")
                
                # Download the ZIP file
                zip_content = download_ruleset(access_token, rule_type)
                
                # Extract and combine rule files
                combined_rules = extract_rules_from_zip(zip_content, rule_type)
                
                # Generate filename with timestamp and rule type
                timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d-%H%M%S')
                rule_type_normalized = rule_type.lower()
                file_key = f"crowdstrike/crowdstrike-{rule_type_normalized}-ruleset-{timestamp}.txt"
                
                logger.info(f"Uploading {rule_type} rules to s3://{bucket_name}/{file_key}")
                
                # Upload to S3
                s3_client.put_object(
                    Bucket=bucket_name,
                    Key=file_key,
                    Body=combined_rules,
                    ContentType='text/plain; charset=utf-8'
                )
                
                success_message = f"Successfully downloaded and saved CrowdStrike {rule_type_normalized} ruleset to {file_key}."
                logger.info(success_message)
                
                results.append({
                    'rule_type': rule_type_normalized,
                    's3_key': file_key,
                    'status': 'success',
                    'message': success_message
                })
                
            except Exception as e:
                error_message = f"Error downloading {rule_type} ruleset: {str(e)}"
                logger.error(error_message, exc_info=True)
                results.append({
                    'rule_type': rule_type.lower(),
                    'status': 'error', 
                    'message': error_message
                })
        
        # Return overall results
        overall_success = all(r['status'] == 'success' for r in results)
        return {
            'statusCode': 200 if overall_success else 207,  # 207 = Multi-Status
            'body': json.dumps({
                'message': f'Processed {len(rule_types)} rule types',
                'results': results,
                'bucket': bucket_name,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        }
        
    except Exception as e:
        error_message = f"Fatal error in CrowdStrike downloader: {str(e)}"
        logger.error(error_message, exc_info=True)
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': error_message,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        }