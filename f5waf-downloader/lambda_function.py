# f5_waf_downloader.py
"""
Lambda function to download the latest F5 WAF attack signatures from F5's documentation site,
chunk them into smaller pieces, and save them to S3 for parallel processing.

This follows the same web scraping approach as the original connector, 
adapted for serverless cloud-native functionality with chunking support.
"""
import os
import json
import logging
import requests
import boto3
import re
from datetime import datetime, timezone

# --- Logging Setup ---
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- Configuration ---
F5_DOC_PAGE_URL = "https://docs.cloud.f5.com/docs-v2/platform/reference/attack-signatures"
DESTINATION_S3_BUCKET_ENV = os.environ.get('DESTINATION_S3_BUCKET')
CHUNK_SIZE = int(os.environ.get('CHUNK_SIZE', '500'))  # Rules per chunk
USER_AGENT = "SAINT-Data-Processor/1.0"

s3_client = boto3.client('s3')

def extract_attack_sigs_path_from_page(html_content: str) -> str:
    """
    Extract the attack-signatures JSON path from the F5 documentation page.
    Uses multiple regex patterns to find the JSON data path.
    """
    # Primary regex - look for the full JSON path
    pattern1 = re.compile(r'(/docs-v2/_next/data/[^"]+attack-signatures\.json)')
    match = pattern1.search(html_content)
    if match:
        json_path = match.group(1)
        logger.info(f"Found JSON path via primary regex: {json_path}")
        return json_path
    
    # Fallback: Extract buildId and construct path manually
    logger.info("Primary regex failed; trying to extract buildId")
    buildid_pattern = re.compile(r'"buildId":\s*"([^"]+)"')
    buildid_match = buildid_pattern.search(html_content)
    
    if buildid_match:
        build_id = buildid_match.group(1)
        json_path = f"/docs-v2/_next/data/{build_id}/platform/reference/attack-signatures.json"
        logger.info(f"Constructed JSON path from buildId: {json_path}")
        return json_path
    
    # Final fallback: Look for any _next/data path that might be related
    logger.warning("BuildId extraction failed; trying broader pattern")
    broad_pattern = re.compile(r'(/docs-v2/_next/data/[^/"]+/[^"]*\.json)')
    broad_matches = broad_pattern.findall(html_content)
    
    # Look for attack-signatures in any of the found paths
    for path in broad_matches:
        if 'attack-signatures' in path:
            logger.info(f"Found attack-signatures path via broad search: {path}")
            return path
    
    logger.error("Could not extract attack-signatures JSON path from page")
    return None

def download_attack_signatures() -> dict:
    """
    Download F5 WAF attack signatures by scraping the documentation page
    and fetching the JSON data.
    """
    headers = {'User-Agent': USER_AGENT}
    
    # Step 1: Fetch the documentation page to get the JSON data path
    logger.info(f"Fetching F5 documentation page: {F5_DOC_PAGE_URL}")
    try:
        doc_response = requests.get(F5_DOC_PAGE_URL, headers=headers, timeout=30)
        doc_response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch F5 documentation page: {e}")
        raise
    
    # Step 2: Extract the JSON path from the page content
    json_path = extract_attack_sigs_path_from_page(doc_response.text)
    if not json_path:
        raise ValueError("Could not find attack-signatures.json link in the documentation page")
    
    # Step 3: Fetch the actual JSON data
    json_url = "https://docs.cloud.f5.com" + json_path
    logger.info(f"Fetching attack signatures JSON from: {json_url}")
    
    try:
        json_response = requests.get(json_url, headers=headers, timeout=30)
        json_response.raise_for_status()
        attack_signatures = json_response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch attack signatures JSON: {e}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse attack signatures JSON: {e}")
        raise
    
    if not attack_signatures:
        raise ValueError("No attack signature data retrieved from F5")
    
    logger.info(f"Successfully downloaded F5 attack signatures data")
    return attack_signatures

def extract_signatures_from_json(json_data: dict) -> list:
    """
    Extract attack signatures from the F5 WAF JSON structure.
    The signatures are nested in pageProps.docData.scope.JsonData
    """
    try:
        # Navigate the nested JSON structure
        page_props = json_data.get('pageProps', {})
        doc_data = page_props.get('docData', {})
        scope = doc_data.get('scope', {})
        signatures = scope.get('JsonData', [])
        
        if not signatures:
            logger.warning("No attack signatures found in JSON data")
            return []
        
        logger.info(f"Extracted {len(signatures)} attack signatures from JSON")
        return signatures
        
    except Exception as e:
        logger.error(f"Failed to extract attack signatures from JSON: {e}")
        return []

def chunk_signatures(signatures: list, chunk_size: int) -> list:
    """
    Split signatures into chunks of specified size.
    Returns list of chunks, where each chunk is a list of signatures.
    """
    chunks = []
    for i in range(0, len(signatures), chunk_size):
        chunk = signatures[i:i + chunk_size]
        chunks.append(chunk)
    
    logger.info(f"Split {len(signatures)} signatures into {len(chunks)} chunks of max {chunk_size} signatures each")
    return chunks

def upload_chunks_to_s3(chunks: list, bucket_name: str, timestamp: str) -> list:
    """
    Upload signature chunks to S3 and return list of uploaded file keys.
    """
    uploaded_files = []
    
    for i, chunk in enumerate(chunks, 1):
        # Create chunk filename
        chunk_number = str(i).zfill(3)  # Zero-padded to 3 digits (001, 002, etc.)
        file_key = f"f5waf/f5-waf-attack-signatures-{timestamp}-chunk-{chunk_number}.json"
        
        # Create chunk structure that matches what the processor expects
        chunk_data = {
            'pageProps': {
                'docData': {
                    'scope': {
                        'JsonData': chunk
                    }
                }
            },
            'chunk_info': {
                'chunk_number': i,
                'total_chunks': len(chunks),
                'signatures_in_chunk': len(chunk),
                'timestamp': timestamp
            }
        }
        
        try:
            logger.info(f"Uploading chunk {i}/{len(chunks)} with {len(chunk)} signatures to s3://{bucket_name}/{file_key}")
            
            # Upload to S3
            s3_client.put_object(
                Bucket=bucket_name,
                Key=file_key,
                Body=json.dumps(chunk_data, indent=2),
                ContentType='application/json; charset=utf-8'
            )
            
            uploaded_files.append(file_key)
            
        except Exception as e:
            logger.error(f"Failed to upload chunk {i}: {e}")
            raise
    
    return uploaded_files

def lambda_handler(event, context):
    """Main handler to fetch F5 WAF attack signatures, chunk them, and upload to S3."""
    if not DESTINATION_S3_BUCKET_ENV:
        logger.error("DESTINATION_S3_BUCKET environment variable is not set.")
        return {'statusCode': 500, 'body': json.dumps({'error': 'Configuration error.'})}

    try:
        # Parse bucket name from environment variable (handle ARN or name)
        bucket_name = DESTINATION_S3_BUCKET_ENV
        if bucket_name.startswith('arn:'):
            bucket_name = bucket_name.split(':')[-1]

        # Download the attack signatures
        logger.info("Downloading F5 WAF attack signatures...")
        attack_signatures_json = download_attack_signatures()
        
        # Extract signatures from the nested JSON structure
        signatures = extract_signatures_from_json(attack_signatures_json)
        if not signatures:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No attack signatures found in downloaded data'})
            }
        
        # Generate timestamp for consistent file naming
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d-%H%M%S')
        
        # Chunk the signatures
        chunks = chunk_signatures(signatures, CHUNK_SIZE)
        
        # Upload chunks to S3
        uploaded_files = upload_chunks_to_s3(chunks, bucket_name, timestamp)
        
        success_message = (
            f"Successfully downloaded {len(signatures)} F5 WAF attack signatures "
            f"and split into {len(chunks)} chunks. "
            f"Uploaded {len(uploaded_files)} files to S3."
        )
        logger.info(success_message)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': success_message,
                'total_signatures': len(signatures),
                'total_chunks': len(chunks),
                'chunk_size': CHUNK_SIZE,
                'uploaded_files': uploaded_files,
                'bucket': bucket_name,
                'timestamp': timestamp
            })
        }

    except Exception as e:
        error_message = f"Failed to download and chunk F5 WAF attack signatures: {str(e)}"
        logger.error(error_message, exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': error_message})
        }