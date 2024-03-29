import dns.resolver
import subprocess
import re
from services import DNSCacheProcessingForWindows
from services.util import DNSRecordsParsing, URLParsing

def getDNSRecordsIPAddress():
    DNSRecords = getDNSRecordsWindows()
    DNSRecordsInList = []
    for DNSRecord in DNSRecords:
        #print(DNSRecord['Record Name'])
        for record in DNSRecord['Records']:
            if record[0] == 'A (Host) Record' and not URLParsing.isLocalHost(record[1]) and URLParsing.getOnlyNumbersOrDot(record[1]):
                DNSRecordsInList.append(record[1])
    return DNSRecordsInList

def getDNSRecordsWindows():

    data = DNSCacheProcessingForWindows.getDNSRecordsWindowsRaw()
    dnsRecords = []
    records = DNSRecordsParsing.splitTextByHyphens(data)
    records = DNSCacheProcessingForWindows.cleanDNSRecords(records)

    return records

getDNSRecordsIPAddress()