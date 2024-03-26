import requests
from tools.environment import *
from tools.APIService import *


# TODO: Write a function to process results from belows Test API calls to VirusTotal?

# TODO: Understand the powershell ipconfig /displaydns and how to integrate

# TODO: Think of how to run script in the background with low usage

# TODO: Think of how to to read records and detect spoofing and or DDoS. Capturing packets?

# For the above todos, remember that you are working with host-recursive_resolver layer of DNS
# So just focus on getting ISP DNS cache and your cache.
# 
# Two goals: Prevent DDoS and Spoofing 

testWebsite = "www.example.com"

testWebsite = "http://www.example.com"

results = URLScanScanURL(testWebsite)
for key in results:
    print(key)