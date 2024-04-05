from services import VirusTotalAPI, URLScanAPI
from controller import DNSResolver
from controller.util import DNSResolverParsing
#import RandomForest
def signatureBasedScans(domainIPAddressesToCheck):
    # VirusTotal and or URLScan
    results = dict()
    for domain in domainIPAddressesToCheck:
        domainScanResult = VirusTotalAPI.VirusTotalScanDomain(domain)
        if domainScanResult:
            results[domain] = {'Domain scan result': domainScanResult}
        else:
            results[domain] = {'Domain scan result': 'N/A'}
        for IPAddress in domainIPAddressesToCheck[domain]:
            results[domain][IPAddress] = VirusTotalAPI.VirusTotalScanIPAddress(IPAddress)
    for result in results:
        print(result, ":", results[result]['Domain scan result'])
        for IPAddress, IPAddressResult in {key: value for key, value in results[result].items() if key != 'Domain scan result'}.items():
            print(IPAddress,":", IPAddressResult)

'''
def domainNameScan(domainIPAddressesToCheck):
    # Uses RandomForest
    RandomForest.predict(domainsList)'''

domainIPAddressesToCheck = DNSResolver.getDNSRecordsDomainIPAddress()

signatureBasedScans(domainIPAddressesToCheck)