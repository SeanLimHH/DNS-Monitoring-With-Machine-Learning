from services import VirusTotalAPI, URLScanAPI
from controller import DNSResolver
from controller.util import DNSResolverParsing
def signatureBasedScans(domainIPAddressesToCheck):
    # VirusTotal and or URLScan
    results = dict()
    for domain in domainIPAddressesToCheck:
        results[domain] = {'Domain scan result': VirusTotalAPI.VirusTotalScanDomain(domain)}
        for IPAddress in domainIPAddressesToCheck[domain]:
            print("Domain",domain)
            print("IP address", IPAddress)
            results[domain][IPAddress] = VirusTotalAPI.VirusTotalScanIPAddress(IPAddress)
    for result in results:
        print(result)

domainIPAddressesToCheck = DNSResolver.getDNSRecordsDomainIPAddress()