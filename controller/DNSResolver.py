import dns.resolver
import subprocess
import re
from services import DNSCacheProcessingForWindows
from services.util import DNSRecordsParsing, URLParsing
from .util import DNSResolverParsing

def getDNSRecordsDomainIPAddress():
    DNSRecords = getDNSRecordsWindows()
    DNSRecordsResults = dict()
    for DNSRecord in DNSRecords:
        #print(DNSRecord['Record Name'])
        for record in DNSRecord['Records']:
            if record[0] == 'A (Host) Record' and not URLParsing.isLocalHost(record[1]) and URLParsing.getOnlyNumbersOrDot(record[1]):
                
                if DNSRecord['Record Name'] not in DNSRecordsResults:
                    DNSRecordsResults[DNSRecord['Record Name']] = []
                DNSRecordsResults[DNSRecord['Record Name']].append(record[1])

    print(DNSRecordsResults)
    return DNSRecordsResults

def getDNSRecordsDomains():
    domainIPAddressMap = getDNSRecordsDomainIPAddress()
    return DNSResolverParsing.getAllDomains(domainIPAddressMap)

def getDNSRecordsIPAddresses():
    domainIPAddressMap = getDNSRecordsDomainIPAddress()
    return DNSResolverParsing.getAllIPAddresses(domainIPAddressMap)

def getDNSRecordsWindows():

    data = DNSCacheProcessingForWindows.getDNSRecordsWindowsRaw()
    dnsRecords = []
    records = DNSRecordsParsing.splitTextByHyphens(data)
    records = DNSCacheProcessingForWindows.cleanDNSRecords(records)

    return records

getDNSRecordsDomainIPAddress()
getDNSRecordsWindows()