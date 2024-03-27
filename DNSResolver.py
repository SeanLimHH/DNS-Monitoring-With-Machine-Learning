import dns.resolver

import subprocess
import re
from tools import DNSCacheProcessingForWindows


resolver = dns.resolver.Resolver()
print(resolver.nameservers)

print(resolver.cache)
# Returns ['8.8.8.8', '8.8.4.4', '8.8.8.8'] on my pc

def getDNSRecordsWindowsPowershell():
    # Here, we are targetting the DNS recursive resolver - ISP for home networks
    try:
        dnsCacheResults = subprocess.run(['ipconfig', '/displaydns'], capture_output=True, text=True)
        if dnsCacheResults.returncode == 0:
            with open("DNSRecursiveResolverCacheRaw.txt", 'w', encoding='utf-8') as f:
                f.write(dnsCacheResults.stdout)
            print(f"Output saved to 'DNSRecursiveResolverCacheRaw.txt'.")
            return dnsCacheResults.stdout # Return textual format. Used for processing
        else:
            print("Error:", dnsCacheResults.stderr)
            return None
    except Exception as e:
        print("Error in viewing DNS resolver cache:", e)
        return None

def viewDNSRecordsWindows():

    data = getDNSRecordsWindowsPowershell()
    dnsRecords = []

    records = DNSCacheProcessingForWindows.splitTextByHyphens(data)
    DNSCacheProcessingForWindows.cleanDNSRecords(records)


def cleanText(text):
    # Remove away the tabs
    cleanedText = re.sub(' ', '', text)
    # Reduce the new lines to one new line
    cleanedText = re.sub(r'\n+', '\n', text)
    cleanedText = cleanedText.strip()
    return cleanedText


dnsCache = viewDNSRecordsWindows()