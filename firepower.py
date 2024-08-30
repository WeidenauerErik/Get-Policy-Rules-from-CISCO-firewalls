import requests
import json
import logging
from requests.auth import HTTPBasicAuth

logging.basicConfig(filename='../logs/cisco_firepower_policies.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#TODO Daten herausfinden
FMC_HOST = "https://<FMC_IP>"
USERNAME = "<DEIN_BENUTZERNAME>"
PASSWORD = "<DEIN_PASSWORT>"

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def get_auth_token():
    auth_url = FMC_HOST + "/api/fmc_platform/v1/auth/generatetoken"
    headers = {'Content-Type': 'application/json'}

    try:
        response = requests.post(auth_url, auth=HTTPBasicAuth(USERNAME, PASSWORD), headers=headers, verify=False)

        if response.status_code == 204:
            auth_token = response.headers.get('X-auth-access-token')
            domain_uuid = response.headers.get('DOMAIN_UUID')  # Kann leer sein
            logging.info("Erfolgreich Authentifizierungstoken abgerufen")
            return auth_token, domain_uuid
        else:
            logging.error(f"Fehler bei der Authentifizierung: {response.status_code} - {response.text}")
            print(f"Fehler: {response.status_code}")
            return None, None

    except Exception as e:
        logging.error(f"Exception während des Authentifizierungsversuchs: {str(e)}")
        print(f"Fehler bei der Authentifizierung: {str(e)}")
        return None, None


# Abrufen der Policies von Firepower
def get_policies():
    auth_token, domain_uuid = get_auth_token()

    if not auth_token:
        print("Authentifizierung fehlgeschlagen.")
        return

    headers = {'Content-Type': 'application/json','X-auth-access-token': auth_token}

    if domain_uuid:
        url = FMC_HOST + f"/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies"
    else:
        url = FMC_HOST + "/api/fmc_config/v1/policy/accesspolicies"

    try:
        response = requests.get(url, headers=headers, verify=False)

        if response.status_code == 200:
            policies = response.json()

            # Speichert alles ab (im Log-file)
            logging.info(f"Erfolgreich Policies abgerufen: {json.dumps(policies, indent=4)}")
            print("Policies erfolgreich abgerufen und im Log gespeichert.")
        else:
            logging.error(f"Fehler beim Abrufen der Policies: {response.status_code} - {response.text}")
            print(f"Fehler: {response.status_code}")

    except Exception as e:
        logging.error(f"Exception während des API-Calls: {str(e)}")
        print(f"Fehler bei der Verbindung zur FMC: {str(e)}")


if __name__ == "__main__":
    get_policies()
