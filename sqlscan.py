import requests
from urllib.parse import urljoin, quote
from bs4 import BeautifulSoup as bs
from pprint import pprint

# Initialize an HTTP session & set the browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(response):
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False


def scan_sql_injection(url):
    # test on URL
    for c in "\"'":
        # URL-encode the quote characters to ensure valid URL
        encoded_char = quote(c)
        new_url = f"{url}{encoded_char}"
        print("[!] Trying", new_url)
        try:
            res = s.get(new_url)
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", new_url)
                return
        except Exception as e:
            print(f"[!] Error trying URL {new_url}: {e}")
            continue

    # test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag["name"]] = input_tag["value"] + c if input_tag["value"] else c
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"

            form_url = urljoin(url, form_details["action"])
            try:
                if form_details["method"] == "post":
                    res = s.post(form_url, data=data)
                elif form_details["method"] == "get":
                    res = s.get(form_url, params=data)

                if is_vulnerable(res):
                    print("[+] SQL Injection vulnerability detected, link:", form_url)
                    print("[+] Form:")
                    pprint(form_details)
                    break
            except Exception as e:
                print(f"[!] Error trying form submission at {form_url}: {e}")
                continue


def main():
    # Command-line parsing code remains the same
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument("-u", "--url", type=str, required=True, help="Target URL for SQL injection scanning")
    args = parser.parse_args()
    
    # Scan the provided URL for SQL injection
    scan_sql_injection(args.url)


if __name__ == "__main__":
    main()
