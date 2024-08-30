import requests
import json
import logging
from requests.auth import HTTPBasicAuth


logging.basicConfig(filename='../logs/cisco_asa_policies.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#TODO herausfinden von Daten
ASA_HOST = "https://<ASA_IP>/api/"
USERNAME = "<DEIN_BENUTZERNAME>"
PASSWORD = "<DEIN_PASSWORT>"

# schaltet SSL Warnungen aus für self-signed Zertifikate
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def get_policies():
    url = ASA_HOST + "objects/networkobjects"

    #TODO das brauchen wir alles?
    # Network Policies - objects/networkobjects
    # ACL Policies - access/rules
    # zweitrangig Nat Policies - nat/rules
    # Service Objekte - objects/serviceobjects
    # objekt groups - objects/networkobjectgroups


    try:
        response = requests.get(url, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)

        # Prüft den Api-Call
        if response.status_code == 200:
            policies = response.json()

            # Speichert alles ab (im Log-file)
            logging.info(f"Erfolgreich Policies abgerufen: {json.dumps(policies, indent=4)}")
            print("abgespeichert")

        else:
            logging.error(f"Fehler beim Abrufen der Policies: {response.status_code} - {response.text}")
            print(f"Fehler: {response.status_code}")

    except Exception as e:
        logging.error(f"Exception während des API-Calls: {str(e)}")
        print(f"Fehler bei der Verbindung zur ASA: {str(e)}")


if __name__ == "__main__":
    get_policies()
