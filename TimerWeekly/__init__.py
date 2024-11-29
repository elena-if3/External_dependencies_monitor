#################1
# MSF-OCB External Dependencies Monitor (2024-05) - internship
#################
 
#################
# Application that checks once a week that the IP ranges provided by Cloudflare are in our ActivityInfo database (DomainDB).
# When a new IP range on Cloudflare is detected, it is added to DomainDB and an email including the new IP range(s) is sent 
# to Dr Watson via Notification Relay, to notify the Infra team about the change.
 
#################
# Reference:
 
# <https://requests.readthedocs.io/en/latest/>
# <https://docs.python.org/3/library/json.html>
# <https://pypi.org/project/python-dotenv/>
# <https://docs.python.org/3/library/os.html>
# <https://docs.python.org/3/library/datetime.html>
# <https://docs.python.org/3/library/secrets.html>
# <https://docs.python.org/3/library/stdtypes.html#string-methods>
# <https://pypi.org/project/logging/>
# <https://urllib3.readthedocs.io/en/stable/>
 
#################
# Imports:

from datetime import date
import json
import requests
import os
import secrets
import string
import azure.functions as func
import logging


#################
# Logger configuration:
# format: 2005-03-19 15:10:26,618 - DEBUG - debug message
logging.basicConfig(format = '%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants:
CONTENT_TYPE = "application/json"

AI_FORM_ID = os.getenv("AI_FORM_ID")
AI_GET_URL = os.getenv("AI_GET_URL")
AI_POST_URL = os.getenv("AI_POST_URL")
AI_TOKEN = os.getenv("AI_TOKEN")

# Functions:

def generate_unique_identifier(length: int = 26) -> str:
    """
    Generate a unique identifier of the given length, which starts with a lower-case letter and
    is followed by a mix of lower-case letters and digits.

    Args:
        length: the length of the identifier to generate
    Returns:
        the generated unique identifier string
    """
    if length < 1:
        raise ValueError("Argument 'length' must be at least 1!")
    first_char = secrets.choice(string.ascii_lowercase)
    remaining_chars = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(length - 1))
    unique_identifier = str(first_char + remaining_chars)
    return unique_identifier


def http_request(method: str, url: str, **kwargs:str) -> object:

    """
    General function for all http requests. Checks for connection errors.

    Args:
        :param method: method: ``GET``, ``POST``.
        :param url: URL for the new:`Request` object.
        :param timeout: (optional) number of seconds Requests will wait to establish a connection to the API.
        :param headers: (optional) Dictionary of HTTP Headers to send with the `Request`.
        :param json: (optional) A JSON serializable Python object to send in the body of the `Request`.
        :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        :param auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
    Returns:
        the http response object
    """
    
    try:
        response = requests.request(method, url, **kwargs)
        response.raise_for_status()
        logger.info("Request successful: %s %s", method, url)
        return response

    except requests.exceptions.HTTPError as e: 
        logger.warning("HTTP Error: %s", e)

    except requests.exceptions.ReadTimeout as e: 
        logger.warning("Timeout Error: %s", e)

    except requests.exceptions.ConnectionError as e: 
        logger.warning("Connection Error: %s", e)

    except requests.exceptions.RequestException as e:
        logger.error("Request Exception: %s", e)


def collect_cloudflare_ips() -> list:
    """
    Read the IP ranges from Cloudflare, which are stored in a list.

    Args:
        none
    Returns:
        list of IP ranges from Cloudflare
    """
    cf_url = "https://api.cloudflare.com/client/v4/ips"
    headers = {
        "Content-Type": CONTENT_TYPE,
    }

    cf_response = http_request("GET", cf_url, headers=headers, timeout=10)

    try:
        cf_response_dict = json.loads(cf_response.text)
        cf_ip_ranges = []

        for ipv4 in cf_response_dict["result"]["ipv4_cidrs"]:
            cf_ip_ranges.append(ipv4)

        for ipv6 in cf_response_dict["result"]["ipv6_cidrs"]:
            cf_ip_ranges.append(ipv6)

        return cf_ip_ranges
    
    except ValueError as e:
        logger.error("Bad json file format: %s", e)
        return []


def collect_activityinfo_ips() -> list:
    """
    Read the IP ranges stored in ActivityInfo, which are stored in a list.

    Args:
	    none
    Returns:
        list of IP ranges from ActivityInfo
    """
  
    headers = {
        "Content-Type": CONTENT_TYPE,
        "Authorization": f"Bearer {AI_TOKEN}"
    }
    ai_response = http_request("GET", f"{AI_GET_URL}{AI_FORM_ID}", headers=headers, timeout=10)
    structured_ai_response = ai_response.json()

    ai_ip_ranges = []

    for item in structured_ai_response:
        ai_ip_ranges.append(item['IP_RANGE'])
            
    return ai_ip_ranges


def detect_new_ip_ranges(l1 : list, l2 : list) -> list:
    """
    Compare two lists in order to obtain a third list including the elements from list #1 that are not present in list #2.
    This function is used in the main function to compare the IP ranges list from Cloudflare (list #1) with the IP ranges 
    list from ActivityInfo (list #2) and store any new Cloudflare IP range in the resulting new list.

    Args:
        two lists
    Returns:
        a new list
    """
    if l1 == l2:
        return []
    new_ip_addresses = []
    for ip in l1:
        if ip not in l2:
            new_ip_addresses.append(ip)
    return new_ip_addresses


def add_new_ip_ranges_to_activityinfo(l : list) -> bool:
    """
    Add the new IP ranges from Cloudflare to ActivityInfo DomainDB.

    Args:
        list (of new Cloudflare IP ranges which are not in ActivityInfo)
    Returns:
        a boolean (True if all the status codes are 200, False if not)
    """
    headers = {
    "Content-Type": CONTENT_TYPE,
    "Authorization": f"Bearer {AI_TOKEN}"
    }
    today = date.today().strftime('%Y-%m-%d')
    waf_type = "Cloudflare"

    unsuccessful_status_list = []

    for ip in l:
        ip_range = ip
        ip_version = "IPv6" if ":" in ip_range else "IPv4"
        payload = json.dumps({
        "changes": [
            {
            "formId": AI_FORM_ID,
            "recordId": generate_unique_identifier(),
            "fields": {
                "DATE_ADDED": today,
                "WAF_TYPE": waf_type,
                "IP_VERSION": ip_version,
                "IP_RANGE": ip_range
            },
            "deleted": False
            }
        ]
        })
        response_ai = http_request("POST", AI_POST_URL, headers=headers, data=payload, timeout=10)

        if response_ai.status_code != 200:
            unsuccessful_status_list.append(response_ai.status_code)
            logger.warning(f"Error status code {response_ai.status_code} returned for IP range {ip_range}.")

    if len(unsuccessful_status_list) == 0:
        return True
    else:
        return False


def send_notification_to_helpdesk(l : list) -> None:
    """
    Use the Notification Relay app to send an email to Dr Watson and notify them that new IP ranges have been added to DomainDB (ActivityInfo).

    Args:
        list (of new IP ranges)
    Returns:
        no return
    """
    nr_url = os.getenv("NR_URL")
    nr_user = os.getenv("NR_USER")
    nr_pass = os.getenv("NR_PASS")
    headers = {
    'Content-Type': CONTENT_TYPE,
    }
    payload = json.dumps({
    "message_subject": "Cloudflare IP range change",
    "message_content": f"The IP address range of Cloudflare has changed\n\nAdded ranges are:\n {l} \n\nThis will need adjustment of firewalls by the Infra team."
    })
    http_request("POST", nr_url, headers=headers, data=payload, auth=(nr_user, nr_pass))


def main(myTimer: func.TimerRequest):

    if myTimer.past_due:
        logging.info("The timer is past due!")

    cloudflare_ip_ranges_list = collect_cloudflare_ips()
    activityinfo_ip_ranges_list = collect_activityinfo_ips()
    
    new_cloudflare_ip_ranges = detect_new_ip_ranges(cloudflare_ip_ranges_list, activityinfo_ip_ranges_list)
    if len(new_cloudflare_ip_ranges) == 0:
        return
    
    status_ok = add_new_ip_ranges_to_activityinfo(new_cloudflare_ip_ranges)
    if not status_ok:
        return
    
    send_notification_to_helpdesk(new_cloudflare_ip_ranges)


#################
# EOF
#################