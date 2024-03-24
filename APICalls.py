import requests
import vt # VirusTotal interface
from tools import environment


apiKey = environment.getEnvironmentVariable("VIRUS_TOTAL_API_KEY")
print("API Key:", apiKey)
client = vt.Client(apiKey)


websiteToCheck = "www.example.com"
domainToCheck = websiteToCheck.split(".")
print(domainToCheck)

# TODO: Write a function to process website vs domain vs subdomain

# TODO: Write a function to abstractify API calls - headers and authentication

# TODO: Write a function to process results from belows Test API calls to VirusTotal?

# TODO: Understand the powershell ipconfig /displaydns and how to integrate

# TODO: Think of how to run script in the background with low usage

# TODO: Think of how to to read records and detect spoofing and or DDoS. Capturing packets?

# For the above todos, remember that you are working with host-recursive_resolver layer of DNS
# So just focus on getting ISP DNS cache and your cache.
# 
# Two goals: Prevent DDoS and Spoofing 

'''
# Test API calls to VirusTotal

# Get information about an URL
urlID = vt.url_id("http://www.virustotal.com")
urlInformation = client.get_object(f'/urls/{urlID}')
print("URL Information", urlInformation)
print("URL Times Submitted", urlInformation.times_submitted)
print("URL Last Analysis Statistics", urlInformation.last_analysis_stats)
'''


# Official API call method to VirusTotal
url = "https://www.virustotal.com/api/v3/domains/{domainToCheck}"

headers = {"accept": "application/json", "x-apikey": apiKey}

response = requests.get(url, headers=headers)

print(response.text)


client.close()