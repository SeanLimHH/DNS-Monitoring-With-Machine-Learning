from util import environment
from .util import URLParsing
import requests
import json
def URLScanURL(urlPath):
    try:
        URLParsing.checkIfValidIPAddress(IPAddress)
    except Exception as error:
        print("URLScanURL error:", error)
        return error
    URLScanAPIKey = environment.getEnvironmentVariable("URL_SCAN_API_KEY")
    print("URLScan Database Scan:")
    headers = {'API-Key': URLScanAPIKey,'Content-Type':'application/json'}
    data = {"url": urlPath, "visibility": "public"}
    response = requests.post(URLScanAPIKey,headers=headers, data=json.dumps(data))
    return response.json()
