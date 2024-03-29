import requests
from .util import URLParsing
import vt
import json
import os
from util import environment

def VirusTotalScanIPAddress(IPAddress):
    try:
        URLParsing.checkIfValidIPAddress(IPAddress)
    except Exception as error:
        print("VirusTotalScanIPAddress error:", error)
        return error
    print("VirusTotal Database Scan:")
    
    VirusTotalScanURL = environment.getEnvironmentVariable("VIRUS_TOTAL_API_IP_ADDRESS_URL")
    VirusTotalAPIKey = environment.getEnvironmentVariable("VIRUS_TOTAL_API_KEY")
    headers = {
        "accept": "application/json",
        "x-apikey": VirusTotalAPIKey 
    }

    response = requests.get(VirusTotalScanURL + IPAddress, headers=headers)
    return response.json()['data']['attributes']['last_analysis_stats']


def VirusTotalScanDomain(domain):
    # We cannot use the client because it lacks domain support.
    print("VirusTotal Domain Scan:")
    try:
        URLParsing.checkIfValidDomain(domain)
    except Exception as error:
        print("VirusTotalScanDomain error:", error)
        return error
    VirusTotalScanURL = environment.getEnvironmentVariable("VIRUS_TOTAL_API_DOMAIN_URL")
    VirusTotalAPIKey = environment.getEnvironmentVariable("VIRUS_TOTAL_API_KEY")
    
    validDomain = os.path.join(VirusTotalScanURL, domain)
    headers = {"accept": "application/json", "x-apikey": VirusTotalAPIKey}

    response = requests.get(validDomain, headers=headers)
    print(response.json()['data']['attributes']['last_analysis_stats'])
    return response.json()['data']['attributes']['last_analysis_stats']
