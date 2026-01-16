#![Repository UUID Validation]
import azure.functions as func
from azure.identity import ClientSecretCredential
import requests
import json
import logging
import os
import uuid
import hmac
import hashlib
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List

app = func.FunctionApp()

class SecurityValidator:
    def __init__(self, function_key: str):
        self.function_key = function_key

        # Load allowed repository UUIDs from environment variables
        self.allowed_repo_uuids = []
        repo_uuids_str = os.environ.get("ALLOWED_REPO_UUIDS", "")
        if repo_uuids_str:
            self.allowed_repo_uuids = [uuid_str.strip() for uuid_str in repo_uuids_str.split(',')]
        logging.info(f"Loaded {len(self.allowed_repo_uuids)} allowed repository UUIDs")

    def verify_signature(self, signature: str, timestamp: str, project_id: str) -> bool:
        try:
            # Verify timestamp is within 5 minutes
            request_time = datetime.fromtimestamp(int(timestamp))
            time_diff = abs((datetime.now() - request_time).total_seconds())

            if time_diff > 300:
                logging.warning(f"Timestamp too old: {time_diff} seconds difference")
                return False

            # Recreate signature
            message = f"{project_id}:{timestamp}"
            expected_signature = hmac.new(
                self.function_key.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()

            is_valid = hmac.compare_digest(signature, expected_signature)
            if not is_valid:
                logging.warning(f"Invalid signature for project {project_id}")

            return is_valid
        except Exception as e:
            logging.error(f"Signature verification error: {str(e)}")
            return False

    def verify_repository_uuid(self, repo_uuid: str) -> bool:
        """Verify that the repository UUID is in the allowed list"""
        if not repo_uuid:
            logging.warning("No repository UUID provided")
            return False

        if not self.allowed_repo_uuids:
            logging.warning("No allowed repository UUIDs configured")
            return False

        is_allowed = repo_uuid in self.allowed_repo_uuids
        if not is_allowed:
            logging.warning(f"Repository UUID {repo_uuid} not in allowed list")

        return is_allowed

@app.route(route="getcredentials", auth_level=func.AuthLevel.FUNCTION)
def getcredentials(req: func.HttpRequest) -> func.HttpResponse:
    request_id = str(uuid.uuid4())
    start_time = datetime.utcnow()
    logging.info(f"[{request_id}] New credential request received")

    # Extract request information for logging
    client_ip = req.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    pipeline_id = req.headers.get('x-pipeline-id', 'unknown')
    timestamp = req.headers.get('x-request-timestamp')
    signature = req.headers.get('x-request-signature')
    repository_uuid = req.headers.get('x-repository-uuid')
    project_id = req.params.get('project', 'unknown')

    logging.info(f"[{request_id}] Request details - Project: {project_id}, Pipeline: {pipeline_id}, IP: {client_ip}, Repository UUID: {repository_uuid}")

    # Initialize security validator
    security = SecurityValidator(
        function_key=os.environ.get("FUNCTION_KEY", "")
    )

    # Validate repository UUID
    if not security.verify_repository_uuid(repository_uuid):
        logging.warning(f"[{request_id}] Repository UUID validation failed: {repository_uuid}")
        return func.HttpResponse("Unauthorized repository", status_code=403)

    # 2. Get and validate required parameters
    app_id = req.params.get('appId')
    app_object_id = req.params.get('objectId')
    tenant_id = req.params.get('tenantId')
    subscription_id = req.params.get('subscriptionId')

    logging.info(f"[{request_id}] Parameter validation - AppID: {app_id is not None}, ObjectID: {app_object_id is not None}, " +
                 f"TenantID: {tenant_id is not None}, SubscriptionID: {subscription_id is not None}, " +
                 f"Timestamp: {timestamp is not None}, Signature: {signature is not None}")

    if not all([app_id, app_object_id, tenant_id, subscription_id, timestamp, signature, project_id, repository_uuid]):
        missing = []
        if not app_id: missing.append("appId")
        if not app_object_id: missing.append("objectId")
        if not tenant_id: missing.append("tenantId")
        if not subscription_id: missing.append("subscriptionId")
        if not timestamp: missing.append("x-request-timestamp")
        if not signature: missing.append("x-request-signature")
        if not project_id: missing.append("project")
        if not repository_uuid: missing.append("x-repository-uuid")

        logging.warning(f"[{request_id}] Missing required parameters: {', '.join(missing)}")
        return func.HttpResponse(f"Missing required parameters: {', '.join(missing)}", status_code=400)

    # 3. Verify request signature
    logging.info(f"[{request_id}] Verifying request signature for project {project_id}")
    if not security.verify_signature(signature, timestamp, project_id):
        logging.warning(f"[{request_id}] Invalid signature for project {project_id}")
        return func.HttpResponse("Invalid request signature", status_code=401)

    try:
        # Generate unique ID for this credential
        credential_id = uuid.uuid4()
        logging.info(f"[{request_id}] Creating temporary credential with ID: {credential_id}")

        # Setup Graph API access
        graph_tenant_id = os.environ.get("GRAPH_TENANT_ID")
        graph_client_id = os.environ.get("GRAPH_CLIENT_ID")
        graph_client_secret = os.environ.get("GRAPH_CLIENT_SECRET")

        if not all([graph_tenant_id, graph_client_id, graph_client_secret]):
            logging.error(f"[{request_id}] Missing Graph API credentials in environment")
            return func.HttpResponse("Server configuration error", status_code=500)

        logging.info(f"[{request_id}] Authenticating with Graph API")
        credential = ClientSecretCredential(
            tenant_id=graph_tenant_id,
            client_id=graph_client_id,
            client_secret=graph_client_secret
        )
        token = credential.get_token("https://graph.microsoft.com/.default")

        # Create temporary secret (1 hour lifetime)
        end_date = datetime.utcnow() + timedelta(hours=1)
        secret_name = f"pipeline-{pipeline_id}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

        logging.info(f"[{request_id}] Creating credential '{secret_name}' for app {app_id}, expires: {end_date.isoformat()}")

        # Create password credential object
        password_credential = {
            "passwordCredential": {
                "displayName": secret_name,
                "endDateTime": end_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "startDateTime": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            }
        }

        # Add password to application using Microsoft Graph REST API
        headers = {
            'Authorization': f'Bearer {token.token}',
            'Content-Type': 'application/json'
        }

        url = f"https://graph.microsoft.com/v1.0/applications/{app_object_id}/addPassword"
        logging.info(f"[{request_id}] Calling Graph API to create secret")

        response = requests.post(url, headers=headers, json=password_credential)

        if response.status_code != 200:
            logging.error(f"[{request_id}] Graph API error: {response.status_code} - {response.text}")
            return func.HttpResponse(f"Failed to create secret: {response.status_code} - {response.text}", status_code=500)

        result = response.json()
        key_id = result.get('keyId', 'unknown')

        # Return credentials
        response_data = {
            "clientId": app_id,
            "clientSecret": result['secretText'],
            "tenantId": tenant_id,
            "subscriptionId": subscription_id,
            "expiresOn": end_date.isoformat(),
            "keyId": key_id,
            "credentialId": str(credential_id)
        }

        # Calculate execution time
        execution_time = (datetime.utcnow() - start_time).total_seconds()
        logging.info(f"[{request_id}] Successfully created credential for project {project_id}, pipeline {pipeline_id}, repository {repository_uuid}")
        logging.info(f"[{request_id}] Secret keyId: {result.get('keyId', 'unknown')}, expires: {end_date.isoformat()}")
        logging.info(f"[{request_id}] Request completed in {execution_time:.2f} seconds")

        return func.HttpResponse(
            json.dumps(response_data),
            status_code=200,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "X-Request-ID": request_id
            }
        )

    except Exception as e:
        # Calculate execution time even for errors
        execution_time = (datetime.utcnow() - start_time).total_seconds()

        # Log detailed error information
        logging.error(f"[{request_id}] Error processing request: {str(e)}", exc_info=True)
        logging.error(f"[{request_id}] Request failed in {execution_time:.2f} seconds")

        return func.HttpResponse(
            json.dumps({
                "error": str(e),
                "requestId": request_id
            }),
            status_code=500,
            headers={
                "Content-Type": "application/json",
                "X-Request-ID": request_id
            }
        )
#######################################################################
### Timer trigger function to clean up expired secrets###
####################################################################
@app.timer_trigger(schedule="0 0 * * * *", arg_name="timer", run_on_startup=True)
def cleanup_expired_secrets(timer: func.TimerRequest) -> None:
    """Timer trigger function that runs every hour to clean up expired secrets

    This function queries Azure AD directly to find secrets created by this function
    that are older than 1.5 hours and deletes them. This approach is stateless and
    resilient to function restarts.
    """
    cleanup_id = str(uuid.uuid4())
    logging.info(f"[{cleanup_id}] Starting cleanup of expired secrets")

    # Setup Graph API access
    graph_tenant_id = os.environ.get("GRAPH_TENANT_ID")
    graph_client_id = os.environ.get("GRAPH_CLIENT_ID")
    graph_client_secret = os.environ.get("GRAPH_CLIENT_SECRET")

    if not all([graph_tenant_id, graph_client_id, graph_client_secret]):
        logging.error(f"[{cleanup_id}] Missing Graph API credentials in environment")
        return

    try:
        credential = ClientSecretCredential(
            tenant_id=graph_tenant_id,
            client_id=graph_client_id,
            client_secret=graph_client_secret
        )
        token = credential.get_token("https://graph.microsoft.com/.default")

        headers = {
            'Authorization': f'Bearer {token.token}',
            'Content-Type': 'application/json'
        }

        # Calculate cutoff time (1.5 hours ago)
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(hours=1, minutes=30)

        # Get app object ID from environment variable
        app_object_id = os.environ.get("APP_OBJECT_ID")
        if not app_object_id:
            logging.warning(f"[{cleanup_id}] APP_OBJECT_ID not configured in environment. Cannot perform cleanup.")
            return

        logging.info(f"[{cleanup_id}] Checking application {app_object_id} for expired secrets")

        total_deleted = 0
        total_failed = 0
        total_checked = 0

        try:
            # Get application details including password credentials
            get_url = f"https://graph.microsoft.com/v1.0/applications/{app_object_id}"
            get_response = requests.get(get_url, headers=headers)

            if get_response.status_code != 200:
                logging.error(f"[{cleanup_id}] Failed to get app {app_object_id}: {get_response.status_code}")
                return

            app_data = get_response.json()
            password_credentials = app_data.get('passwordCredentials', [])

            # Find secrets matching our naming pattern and older than cutoff
            for cred in password_credentials:
                display_name = cred.get('displayName', '')
                key_id = cred.get('keyId', '')
                start_date_str = cred.get('startDateTime', '')

                # Check if this is a secret created by our function (starts with 'pipeline-')
                if not display_name.startswith('pipeline-'):
                    continue

                total_checked += 1

                # Parse the creation time from startDateTime
                try:
                    start_date = datetime.strptime(start_date_str, "%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    try:
                        # Try alternative format
                        start_date = datetime.strptime(start_date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                    except ValueError:
                        logging.warning(f"[{cleanup_id}] Could not parse date for secret {key_id}: {start_date_str}")
                        continue

                # Check if secret is older than cutoff time
                if start_date < cutoff_time:
                    age_hours = (current_time - start_date).total_seconds() / 3600
                    logging.info(f"[{cleanup_id}] Found expired secret '{display_name}' (age: {age_hours:.2f} hours)")

                    # Delete the secret
                    try:
                        delete_url = f"https://graph.microsoft.com/v1.0/applications/{app_object_id}/removePassword"
                        delete_response = requests.post(delete_url, headers=headers, json={"keyId": key_id})

                        if delete_response.status_code == 204:
                            logging.info(f"[{cleanup_id}] Successfully deleted expired secret {key_id} ('{display_name}')")
                            total_deleted += 1
                        else:
                            logging.error(f"[{cleanup_id}] Failed to delete secret {key_id}: {delete_response.status_code} - {delete_response.text}")
                            total_failed += 1
                    except Exception as e:
                        logging.error(f"[{cleanup_id}] Error deleting secret {key_id}: {str(e)}")
                        total_failed += 1
                else:
                    age_hours = (current_time - start_date).total_seconds() / 3600
                    logging.debug(f"[{cleanup_id}] Secret '{display_name}' is still valid (age: {age_hours:.2f} hours)")

            logging.info(f"[{cleanup_id}] Cleanup complete. Checked: {total_checked} secrets, Deleted: {total_deleted}, Failed: {total_failed}")

        except Exception as e:
            logging.error(f"[{cleanup_id}] Error processing application: {str(e)}")

    except Exception as e:
        logging.error(f"[{cleanup_id}] Error during cleanup process: {str(e)}", exc_info=True)
