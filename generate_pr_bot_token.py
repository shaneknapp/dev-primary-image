import time
import jwt
import requests

import os
import sys
import logging

from base64 import b64encode
from nacl import encoding, public


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()


def get_installation_token(CLIENT_ID, private_key):
    """
    Create an installation token from a private key. 
    1. Create a JWT with the private key.
    2. Exchagne the JWT for an installation token which can be used to interact with git repos. 
    """
    # Create a JWT using the private key
    payload = {
        'iat': int(time.time()) - 60,  # issued at (current time - 60 seconds)
        'exp': int(time.time()) + (10 * 60),  # expiration (10 minutes from now)
        'iss': CLIENT_ID, 
    }
    try:
        # Create JWT token
        jwt_token = jwt.encode(payload, private_key, algorithm='RS256')
    except jwt.exceptions.InvalidTokenError as e:
        logger.error(f"Failed to create JWT token: {e}")

    # GitHub API URL for listing installations of the GitHub App
    INSTALLATIONS_URL = 'https://api.github.com/app/installations'

    # Make the API call to authenticate as the GitHub App and list installations
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {jwt_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        response = requests.get(INSTALLATIONS_URL, headers=headers)
        if response.status_code == 200:
            installations = response.json()
            if installations:
                # Get the installation ID (from the first installation)
                installation_id = installations[0]['id']
            
                # URL for creating an installation access token
                INSTALLATION_TOKEN_URL = f'https://api.github.com/app/installations/{installation_id}/access_tokens'

                # Permissions for the token 
                permissions = {'actions': 'write', 'secrets': 'write', 'contents': 'write', 'metadata': 'read', 'statuses': 'read', 'workflows': 'write', 'pull_requests': 'write', 'administration': 'read', 'repository_custom_properties': 'write'}
              
                # Create the installation access token
                token_response = requests.post(INSTALLATION_TOKEN_URL, headers=headers, json={'permissions': permissions})

                if token_response.status_code == 201:
                    installation_token = token_response.json()['token']
                    logger.info(f"Installation Access Token has been created.")
                    return installation_token
                else:
                    logger.info(f"Failed to create installation access token: {token_response.status_code}")
                    sys.exit(1)
            else:
                logger.info("No installations found for this GitHub App.")
                sys.exit(1)
        else:
            logger.info(f"Failed to list installations: {response.status_code}")
            sys.exit(1)

    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":

    CLIENT_ID = os.getenv('CLIENT_ID')
    PRIVATE_KEY_PATH = os.getenv('PRIVATE_KEY_SECRET')

    installation_token = get_installation_token(CLIENT_ID, PRIVATE_KEY_PATH)
    
    env_file = os.getenv('GITHUB_ENV')
    with open(env_file, "a") as myfile:
        myfile.write(f"TOKEN={installation_token}\n")

