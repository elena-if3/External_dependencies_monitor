#################
# MSF-OCB External Dependencies Monitor (2024-05) - internship
#################
 
#################
# PyTest unit tests for 'TimerWeekly.py'
 
#################
# Reference:
# <https://docs.pytest.org/>
# <https://coverage.readthedocs.io/en/7.5.2/>
# <https://docs.python.org/3/library/unittest.html>
# <https://docs.python.org/3/library/unittest.mock.html>
# <https://pypi.org/project/python-dotenv/>
# <https://docs.python.org/3/library/os.html>
# <https://docs.python.org/3/library/json.html>
# <https://docs.python.org/3/library/datetime.html>
# <https://labix.org/mocker>
# <https://pytest-cov.readthedocs.io/en/latest/>
# <https://pytest-mock.readthedocs.io/en/latest/>
# 
 
#################
# Imports:
import pytest
from unittest.mock import Mock, patch, MagicMock
import json
import os
import requests
from TimerWeekly import main as timer_main
import azure.functions as func


# Note: Import functions from 'TimerWeekly.py' into the current namespace
from TimerWeekly import http_request, collect_cloudflare_ips, collect_activityinfo_ips, detect_new_ip_ranges, add_new_ip_ranges_to_activityinfo, send_notification_to_helpdesk

#################
# Test http_request function

def test_http_request_success(requests_mock):
    requests_mock.get('http://example.com', status_code=200)
    response = http_request('GET', 'http://example.com')
    assert response.status_code == 200

def test_http_request_http_error(requests_mock):
    requests_mock.get('http://example.com', status_code=404)
    response = http_request('GET', 'http://example.com')
    assert response is None

def test_http_request_timeout(requests_mock):
    requests_mock.get('http://example.com', exc=requests.exceptions.ReadTimeout)
    response = http_request('GET', 'http://example.com')
    assert response is None

def test_http_request_connection_error(requests_mock):
    requests_mock.get('http://example.com', exc=requests.exceptions.ConnectionError)
    response = http_request('GET', 'http://example.com')
    assert response is None

def test_http_request_with_custom_timeout(requests_mock):
    requests_mock.get('http://example.com', status_code=200)
    response = http_request('GET', 'http://example.com', timeout=5)
    assert response.status_code == 200


#################
# Test collect_cloudflare_ips function

def test_collect_cloudflare_ips(mocker):
    mock_httprequest = mocker.patch('TimerWeekly.http_request')
    mock_response = Mock()
    mock_response.text = json.dumps({
        "result": {
            "ipv4_cidrs": [
                "192.0.2.0/24",
                "198.51.100.0/24"
            ],
            "ipv6_cidrs": [
                "2001:db8::/32",
                "2001:db8:abcd::/48"
            ]
        }
    })
    mock_httprequest.return_value = mock_response
    result = collect_cloudflare_ips()
    expected_result = [
        "192.0.2.0/24",
        "198.51.100.0/24",
        "2001:db8::/32",
        "2001:db8:abcd::/48"
    ]
    assert result == expected_result
    mock_httprequest.assert_called_once_with("GET", "https://api.cloudflare.com/client/v4/ips", headers={"Content-Type": "application/json"}, timeout=10)

#################
# Test collect_activity_info_ips

@patch('TimerWeekly.http_request')  
@patch('TimerWeekly.AI_TOKEN', new='mock_token')  
@patch('TimerWeekly.AI_GET_URL', new='mock_url')  
@patch('TimerWeekly.AI_FORM_ID', new='mock_form_id')
@patch('TimerWeekly.CONTENT_TYPE', new='mock_content_type')
def test_collect_activityinfo_ips(mock_http_request):
    # Mock the response from the http_request function
    mock_response = MagicMock()
    mock_response.json.return_value = [
        {'IP_RANGE': '192.168.0.1/24'},
        {'IP_RANGE': '192.168.1.1/24'}
    ]
    mock_http_request.return_value = mock_response

    # Call the function to be tested
    result = collect_activityinfo_ips()

    # Assert that the http_request function was called with the correct arguments
    mock_http_request.assert_called_once_with("GET", f"{'mock_url'}{'mock_form_id'}", headers={
        "Content-Type": 'mock_content_type',
        "Authorization": f"Bearer {'mock_token'}"
    }, timeout=10)

    # Assert that the result is as expected
    assert result == ['192.168.0.1/24', '192.168.1.1/24']


#################
# Test detect_new_ip_ranges function

def test_detect_new_ip_ranges():
    # Test case 1: Lists with no new IP addresses
    l1 = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    l2 = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert detect_new_ip_ranges(l1, l2) == []

    # Test case 2: Lists with one new IP address
    l1 = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]
    l2 = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert detect_new_ip_ranges(l1, l2) == ["4.4.4.4"]

    # Test case 3: Lists with multiple new IP addresses
    l1 = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]
    l2 = ["1.1.1.1", "2.2.2.2"]
    assert detect_new_ip_ranges(l1, l2) == ["3.3.3.3", "4.4.4.4"]

    # Test case 4: Lists with no common IP addresses
    l1 = ["1.1.1.1", "2.2.2.2"]
    l2 = ["3.3.3.3", "4.4.4.4"]
    assert detect_new_ip_ranges(l1, l2) == ["1.1.1.1", "2.2.2.2"]

    # Test case 5: Empty lists
    l1 = []
    l2 = []
    assert detect_new_ip_ranges(l1, l2) == []

    # Test case 6: One empty list
    l1 = ["1.1.1.1", "2.2.2.2"]
    l2 = []
    assert detect_new_ip_ranges(l1, l2) == ["1.1.1.1", "2.2.2.2"]


#################
# Test add_new_ip_ranges_to_activityinfo function

# Fixture to mock the requests.request function
@pytest.fixture
def mock_requests(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr("requests.request", mock)
    yield mock

def test_add_new_ip_ranges_to_activityinfo(mock_requests):
    # Define a sample list for testing
    ips = ["192.168.1.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"]

    # Call the function to test
    add_new_ip_ranges_to_activityinfo(ips)

    # Verify that requests.request was called twice (once for each IP range)
    assert mock_requests.call_count == len(ips)


#################
# Test send_notification_to_helpdesk function

# Mock environment variables for testing
@pytest.fixture
def mock_env_variables(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NR_URL", "mocked_nr_url")
    monkeypatch.setenv("NR_USER", "mocked_user")
    monkeypatch.setenv("NR_PASS", "mocked_pass")

# Define a sample list for testing
@pytest.fixture
def sample_list():
    return ["192.168.1.0/24", "10.0.0.0/8"]

# Define the expected payload
@pytest.fixture
def expected_payload(sample_list: list[str]):
    return json.dumps({
        "message_subject": "Cloudflare IP range change",
        "message_content": f"The IP address range of Cloudflare has changed\n\nAdded ranges are:\n {sample_list} \n\nThis will need adjustment of firewalls by the Infra team."
    })

def test_send_notification_to_helpdesk(sample_list: list[str], expected_payload: str):
    # Patching the requests.request method to prevent actual network calls
    with patch('requests.request') as mocked_request:

        # Call the function
        send_notification_to_helpdesk(sample_list)

        # Check if requests.request is called with the expected arguments
        mocked_request.assert_called_once_with(
            "POST", os.getenv("NR_URL"),
            headers={'Content-Type': 'application/json'},
            data=expected_payload,
            auth=(os.getenv("NR_USER"), os.getenv("NR_PASS"))
        )


#################
# Test main function

@pytest.fixture
def timer_request():
    return Mock(spec=func.TimerRequest, past_due=False)

# Define sample lists for testing
@pytest.fixture
def cloudflare_ip_ranges():
    return ["192.168.0.1/24", "10.0.0.1/24"]

@pytest.fixture
def activityinfo_ip_ranges():
    return ["10.0.0.1/24"]

def test_main(timer_request, cloudflare_ip_ranges, activityinfo_ip_ranges):
    # Use a single `with` statement to apply all patches
    with patch('TimerWeekly.collect_cloudflare_ips', return_value=cloudflare_ip_ranges), \
         patch('TimerWeekly.collect_activityinfo_ips', return_value=activityinfo_ip_ranges), \
         patch('TimerWeekly.add_new_ip_ranges_to_activityinfo') as mock_add_new_ips, \
         patch('TimerWeekly.send_notification_to_helpdesk') as mock_send_notification:

        # Call the main function with the mocked timer_request
        timer_main(timer_request)
        
        # Expected new IPs that should be detected and added
        expected_new_ips = ["192.168.0.1/24"]
        
        # Check if the add_new_ip_ranges_to_activityinfo was called correctly
        mock_add_new_ips.assert_called_once_with(expected_new_ips)
        
        # Check if the send_notification_to_helpdesk was called correctly
        mock_send_notification.assert_called_once_with(expected_new_ips)


#################
# EOF
#################