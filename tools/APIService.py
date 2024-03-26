import os
import requests
import json
import vt
import re
from .environment import *

def URLScanScanURL(urlPath):
    urlPath = returnValidURLFrom(urlPath)
    print("URLScan Database Scan:")
    URLScanAPIKey = getEnvironmentVariable("URL_SCAN_API_KEY")
    headers = {'API-Key': URLScanAPIKey,'Content-Type':'application/json'}
    data = {"url": urlPath, "visibility": "public"}
    response = requests.post(getEnvironmentVariable("URL_SCAN_API_URL"),headers=headers, data=json.dumps(data))
    return response.json()


def VirusTotalScanURL(urlPath):
    urlPath = returnValidURLFrom(urlPath)
    print("VirusTotal Database Scan:")
    VirusTotalAPIKey = getEnvironmentVariable("VIRUS_TOTAL_API_KEY")
    client = vt.Client(VirusTotalAPIKey)
    urlID = vt.url_id(urlPath)
    urlInformation = client.get_object(f'/urls/{urlID}')
    print("URL Information", urlInformation)
    print("URL Times Submitted", urlInformation.times_submitted)
    print("URL Last Analysis Statistics", urlInformation.last_analysis_stats)
    client.close()
    return urlInformation


def VirusTotalScanDomain(urlPath):
    domain = returnValidDomainsFrom(urlPath)
    # We cannot use the client because it lacks domain support.
    print("VirusTotal Domain Scan:")
    VirusTotalScanURL = getEnvironmentVariable("VIRUS_TOTAL_API_URL")
    VirusTotalAPIKey = getEnvironmentVariable("VIRUS_TOTAL_API_KEY")
    
    validDomain = os.path.join(VirusTotalScanURL, domain)
    headers = {"accept": "application/json", "x-apikey": VirusTotalAPIKey}

    response = requests.get(validDomain, headers=headers)
    return response.json()['data']


def returnValidURLFrom(urlPath):
    # Tested the following pattern with https://regex101.com/r/LOQEXz/2 and 
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions/Cheatsheet#character_classes
    
    isMissingHTTP = re.compile("^https?://")
    if not isMissingHTTP.search(urlPath):
        raise Exception("HTTP is missing or URL is invalid!")

    standardURLFormat = re.compile("^https?://www(.[a-z0-9]+)+")
    match = standardURLFormat.search(urlPath)
    if match:
        return match.group(0)
    else:
        raise Exception("URL is invalid")

def returnValidDomainsFrom(urlPath):
    urlPath = returnValidURLFrom(urlPath)
    domain = urlPath.split(".")
    domain = domain[1:]
    validDomain = ".".join(domain)
    return validDomain
