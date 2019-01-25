import jwt
import json
import boto3
import base64
import requests
from botocore.exceptions import ClientError

def is_revoked(token):
    table_name = "rentalated-accounts-db-RevokedTokensTable-1VIEA9RVNWJKG"
    ## ^^ this is a slight problem
    client = boto3.client("dynamodb")
    response = client.get_item(
        TableName=table_name,
        Key={
            'accessToken': {
                'S': token
            }
        }
    )
    if response["Item"]:
        return True
    else:
        return False

def decode_auth_token(auth_header):
    """
    Validates the auth token
    :param auth_token:
    :return: integer|string
    """
    errorResponse = {
        "statusCode": 400,
        "body": {
            "valid": False,
            "payload": None,
            "error_message": "Bad auth token."
        }
    }
    successResponse = {
        "statusCode": 200,
        "body": {
            "valid": True,
            "payload": None,
            "error_message": None
        }
    }
    response = errorResponse

    SECRET_KEY = get_secret()

    # if the auth header exists, has the "Bearer <token>" pattern, the parsed token 
        # decodes properly with the secret, and the token is not expired, 
        # then we toggle the response from error to success.
    if auth_header:
        if len(auth_header.split()) > 1:
            auth_token = auth_header.split()[1]
            try:
                payload = jwt.decode(auth_token, SECRET_KEY, algorithms=["HS256"])
                if not is_revoked(auth_token):
                    successResponse["body"]["payload"] = payload["sub"]
                    response = successResponse     
                else: 
                    response["body"]["error_message"] = "Unauthorized: user not logged in."       
            except (jwt.ExpiredSignatureError,  jwt.InvalidTokenError) as error:
                response["body"]["error_message"] = error
    response["body"] = json.dumps(response["body"])
    return response

def get_secret():
    # CURTIS: this function is basically provided by AWS when you store a secret
        # in secretsmanager

    secret_name = "secret_key"
    region_name = "us-east-2"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)['SECRET_KEY']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret

def token_verifier(event, context):
    try: 
        body = json.loads(event["body"])
        auth_header = body["auth_header"]
    except Exception as e: 
        print(e)
        return {
            "statusCode": 400,
            "body": "Could not parse auth header from request. \
                Request body should be a json string with the auth header \
                of your own incoming request sent under the key auth_header."
        }
    finally: 
        return decode_auth_token(auth_header)
