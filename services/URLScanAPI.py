from util import environment
from .util import URLParsing
import requests
import json
def URLScanURL(urlPath):
    if URLParsing.isValidURL(urlPath):
        URLScanAPIKey = environment.getEnvironmentVariable("URL_SCAN_API_KEY")
        print("URLScan Database Scan:")
        headers = {'API-Key': URLScanAPIKey,'Content-Type':'application/json'}
        data = {"url": urlPath, "visibility": "public"}
        response = requests.post(URLScanAPIKey,headers=headers, data=json.dumps(data))
        return response.json()
