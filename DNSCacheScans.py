from services import VirusTotalAPI, URLScanAPI
from controller import DNSResolver
from controller.util import DNSResolverParsing
import pandas as pd
import IsolationForest


def signatureBasedScans(domainIPAddressesToCheck):
    # VirusTotal and or URLScan
    domainResults = dict()
    domainIPAddressResults = dict()
    for domain in domainIPAddressesToCheck:
        domainScanResult = VirusTotalAPI.VirusTotalScanDomain(domain)
        domainIPAddressResults[domain] = {}
        if domainScanResult:
            domainResults[domain] = domainScanResult
        else:
            domainResults[domain] = {'N/A'}
        for IPAddress in domainIPAddressesToCheck[domain]:
            domainIPAddressResults[domain][IPAddress] = VirusTotalAPI.VirusTotalScanIPAddress(IPAddress)

    return domainResults, domainIPAddressResults

def initialiseAbnormalScanResultsClassifier(scanResultsMatrix):
    print("Checking if Isolation Forest classifier for Virus Total Scan Results is built...")
    try:
        isolationForestVirusClassifier = IsolationForest.loadIsolationForestVirusTotalResults()
    except FileNotFoundError:
        print("Isolation Forest algorithm for Virus Total Scan Results is not yet set up. Setting it up now...")
        IsolationForest.buildIsolationForestVirusTotalResults(scanResultsMatrix)

    print("The Isolation Forest algorithm for Virus Total Scan Results is set up and ready for prediction.\n")


def convertDictionaryResultsToMatrix(data):
    
    df = pd.DataFrame.from_dict(data, orient='index') # Keys of dictionary becomes the row labels.
    
    return df[['malicious', 'suspicious', 'undetected', 'harmless', 'timeout']].values

def convertSignatureScanResultsToMatrix(domainIPAddressResults):

    matrix = []
    for domainName in domainIPAddressResults:
        # print("\n\n\nDomain name:", domainName)
        for IPAddress in domainIPAddressResults[domainName]:
            # print("IP Address", IPAddress)
            # print("Assessment of IP Address:", domainIPAddressResults[domainName][IPAddress])
            matrix.append(list(domainIPAddressResults[domainName][IPAddress].values()))
    return matrix


'''
# Performance of isolation forest on new unseen data is pretty poor - it falsely flags out abnormalies
# when they are all normal data.
# Hence, this part is experimental and can be ignored.


scanResultsMatrix = convertSignatureScanResultsToMatrix(domainIPAddressResults)
initialiseAbnormalScanResultsClassifier(scanResultsMatrix)


for result in scanResultsMatrix:
    IsolationForest.predictVirusTotalResults([result])
'''
def prettifyOutput(domainAnddomainIPAddressResults):

    prettifiedOutput = ""
    domainResults, domainIPAddressResults = domainAnddomainIPAddressResults
    for domainName in domainResults:
        print(f"\n\n\nDomain name: {domainName}")
        print(f"Domain name scanned results: {domainResults[domainName]}")
        IPAddresses = domainIPAddressResults[domainName]
        for index, IPAddress in enumerate(IPAddresses):
            print(f"IP Address {index+1}: {IPAddress}: {IPAddresses[IPAddress]}")
    return prettifiedOutput


def run():
    domainIPAddressesToCheck = DNSResolver.getDNSRecordsDomainIPAddress()
    domainAnddomainIPAddressResults = signatureBasedScans(domainIPAddressesToCheck)
    print(prettifyOutput(domainAnddomainIPAddressResults))
run()