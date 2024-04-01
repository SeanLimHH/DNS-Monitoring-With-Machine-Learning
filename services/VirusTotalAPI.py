import requests
from .util import URLParsing
import vt
import json
import os
from util import environment

def VirusTotalScanIPAddress(IPAddress):
    if URLParsing.isValidIPAddress(IPAddress):
    
        VirusTotalScanURL = environment.getEnvironmentVariable("VIRUS_TOTAL_API_IP_ADDRESS_URL")
        VirusTotalAPIKey = environment.getEnvironmentVariable("VIRUS_TOTAL_API_KEY")
        headers = {
            "accept": "application/json",
            "x-apikey": VirusTotalAPIKey 
        }

        response = requests.get(VirusTotalScanURL + IPAddress, headers=headers)
        
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats']


def VirusTotalScanDomain(domain):
    # We cannot use the client because it lacks domain support.
    if URLParsing.isValidDomain(domain):
        VirusTotalScanURL = environment.getEnvironmentVariable("VIRUS_TOTAL_API_DOMAIN_URL")
        VirusTotalAPIKey = environment.getEnvironmentVariable("VIRUS_TOTAL_API_KEY")
        
        validDomain = os.path.join(VirusTotalScanURL, domain)
        headers = {"accept": "application/json", "x-apikey": VirusTotalAPIKey}

        response = requests.get(validDomain, headers=headers)
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats']