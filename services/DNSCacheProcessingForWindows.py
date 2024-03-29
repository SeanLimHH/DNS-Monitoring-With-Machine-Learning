import re
import dns
import subprocess
from .util import DNSRecordsParsing


resolver = dns.resolver.Resolver()
print(resolver.nameservers)

print(resolver.cache)
# Returns ['8.8.8.8', '8.8.4.4', '8.8.8.8'] on my pc

def getDNSRecordsWindowsRaw():
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



def cleanDNSRecords(records):

    noWhiteSpaceOnlyPropertiesRecords = {}
    cleanedRecords = []
    for recordPropertiesKeyValue in records:
        currentRecordName = ''
        recordPropertiesKeyValue = recordPropertiesKeyValue.split("\n")
        recordPropertiesKeyValue = [item.strip() for item in recordPropertiesKeyValue if item.strip()]
        recordPropertiesKeyValue = [item.split(':') if ':' in item else None for item in recordPropertiesKeyValue]
        recordPropertiesKeyValue = [item for item in recordPropertiesKeyValue if item is not None]
        for recordPropertyKeyValue in recordPropertiesKeyValue:
            recordPropertyKeyValue[0] = re.sub(r' \.+', '', recordPropertyKeyValue[0]).strip()
            recordPropertyKeyValue[1] = recordPropertyKeyValue[1].strip()
            cleanedRecords.append(recordPropertyKeyValue)


    cleanedGroupedRecords = DNSRecordsParsing.clusterIntoGroups(cleanedRecords,'Record Name')

    for group in cleanedGroupedRecords:
        print("\n\nRecord Name:",group['Record Name'])
        for record in group['Records']:
            print(record)

    print("End of clean DNS record")
    return cleanedGroupedRecords


