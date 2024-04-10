import os
import boto3
import logging
import jwt

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cognito_client = boto3.client("cognito-idp") 


AWS_REGION = os.getenv("AWS_REGION")
AWS_USER_POOL = os.getenv("AWS_USER_POOL", "")
AWS_CLIENT_IDS = os.getenv("AWS_CLIENT_ID", "").split(",")
ALLOWED_SCOPES = os.getenv("ALLOWED_SCOPES", "").split(",")
ALLOWED_ROLES = os.getenv("ALLOWED_ROLES", "").split(",")
JWKS_URL = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{AWS_USER_POOL}/.well-known/jwks.json"

client = jwt.PyJWKClient(JWKS_URL)

def get_signing_key_from_jwt(token, client):
    return client.get_signing_key_from_jwt(token)

def get_attributes(data: list) -> dict:
    """Extracts the user attributes from the cognito response"""
    attributes = {}
    for attribute in data["UserAttributes"]:
        attributes[attribute["Name"]] = attribute["Value"]

    return attributes

def get_attribute(key: str, data: dict) -> str:
    """extracts a single attribute from the user attributes"""
    return data.get(key, "")

def decode_jwt(token, key):
    """decodes and validates a jwt token against
    the JWKS endpoint of the cognito user pool
    
    A separate check is made to ensure that the client_id
    in the token is valid and is one of the allowed client_ids

    Note: cognito does not add an audience to JWTs
    so we need to disable the verify_aud option

    """
    token = jwt.decode(
        token,
        key=key,
        algorithms=["RS256"],
        options={
            "verify_aud": False,
            "verify_signature": True
        },
    )
    if token['client_id'] not in AWS_CLIENT_IDS:
        raise Exception('Invalid client_id')
    return token

def validate_token(token, client):
    key = get_signing_key_from_jwt(token, client)
    return decode_jwt(token, key.key)


def handler(event, context):
    """This function authorizes API gateway requests"""
    try:
        authorized = False
        scopes_raw = None
        roles_raw = None
        
        # validate token against JWKS well-known endpoint
        access_token = event["headers"]["authorization"].split(" ")[1]
        token = validate_token(access_token, client)
        scopes_raw = token["scope"]
        scopes = set(scopes_raw.split(" "))
        
        # if scope in ALLOWED_SCOPES then this is client credentials token
        if scopes.intersection(set(ALLOWED_SCOPES)):
            logger.info("Authorized client credentials token")
            authorized = True
        
        # else use the existence of groups to assume user access token
        # to get the user roles a call to cognito is made
        # and the roles are checked against the allowed roles
        elif "cognito:groups" in token:
            response = cognito_client.get_user(AccessToken=access_token)
            attributes = get_attributes(response)
            roles_raw = get_attribute("custom:roles", attributes)
            roles = roles_raw.split("|")
            if set(roles).intersection(set(ALLOWED_ROLES)):
                logger.info("Authorized user access token")
                authorized = True

        return {
            "isAuthorized": authorized,
            "context": {
                "scopes": scopes_raw,
                "roles": roles_raw,
            }
        }

    except Exception as e:
        logging.info(f'Error - {e}')
        return {"isAuthorized": False}