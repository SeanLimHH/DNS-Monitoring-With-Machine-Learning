from scapy.all import sniff, DNS, IP, DNSQR, DNSRR, UDP, sr1, ls
import socket
import IsolationForest, RandomForest
import inspect
import time
'''
The motivation here is to have a list of common query types.
If a packet has a DNS query not in the list of common query types, we could flag it.
https://en.wikipedia.org/wiki/List_of_DNS_record_types


https://bluecatnetworks.com/blog/know-the-eight-most-common-dns-records/

A, AAAA, CNAME, PTR, NS, MX, SOA, TXT


https://bluecatnetworks.com/blog/the-top-four-dns-response-codes-and-what-they-mean/

Responses are typically: NoError, NXDomain, ServFail, Refused

The above, although are all common, does not imply safety. But we will first focus on
basic measures for now.

We want to mitigate Domain Generation Attacks here. Possibly using machine learning? Random Forest?
'''



def checkPackets(packetsList):
    for packet in packetsList:
        print()
        encodedQueryResponsePacket = encodePacketQueryResponse(packet)
        packetDomainName = None
        if packet.haslayer(DNSQR) and packet[DNSQR].qname:
            packetDomainName = packet[DNSQR].qname.decode()
        elif packet.haslayer(DNSRR) and packet[DNSRR].rrname:
            packetDomainName = packet[DNSRR].rrname.decode()
        else:
            IPAddress = packet[IP].src
            print("Packet's source IP address:", IPAddress)

        if packetDomainName:
            print("Packet's domain name:", packetDomainName)
            RandomForest.predictDomainName([packetDomainName])
        else:
            print("This packet has no domain name!")
        RandomForest.predictQueryResponse(encodedQueryResponsePacket)


        #TODO This is just for checks. Can remove eventually
        #viewDNSPropertiesOfPackets(packet)

        checkQueryResponseLengths(packet) # Isolation Forest checks for query and response lengths

commonDNSQueryTypes = [1, 28, 5, 12, 2, 15, 6, 16]
commonDNSReturnCodes = [0, 2, 3, 5]
sniffedPackets = []

def extractPacketsWithoutTimestamp(sniffedPackets):
    # Returns a list of just the packets without the timestamps
    return [element[0] for element in sniffedPackets]

def encodePacketQueryResponse(packet):
    suspicious = False
    DNSPacketEncodedForRandomForest = []

    # The structure is df[['qd_qtype', 'qd_qname_len', 'ar_type', 'ar_rdata_len']]
    if DNS in packet:
        DNSPacket = packet[DNS]

        if DNSPacket.qd.qtype:
            DNSPacketEncodedForRandomForest.append(DNSPacket.qd.qtype)
        else:
            DNSPacketEncodedForRandomForest.append(0)


        if packet.haslayer(DNSQR):
            if packet[DNSQR].qname:
                DNSPacketEncodedForRandomForest.append(len(packet[DNSQR].qname))
            else:
                DNSPacketEncodedForRandomForest.append(0)
        else:
            DNSPacketEncodedForRandomForest.append(0)

        if DNSPacket.rcode:
            DNSPacketEncodedForRandomForest.append(DNSPacket.rcode)
        else:
            DNSPacketEncodedForRandomForest.append(0)

        if packet.haslayer(DNSRR):
            if packet[DNSRR].rdata:
                DNSPacketEncodedForRandomForest.append(len(packet[DNSRR].rdata))
            else:
                DNSPacketEncodedForRandomForest.append(0)
        else:
            DNSPacketEncodedForRandomForest.append(0)

        return [DNSPacketEncodedForRandomForest]
    else:
        print("Packet does not contain DNS information.")

    return suspicious

    # Random forest would be strong here due to categorical nature. Bundle with packet length
    # Use random forest to independently and separate scan the query type and response type.



def checkQueryResponseLengths(packet): # DNS exfiltration or DNS tunnelling
    if DNS in packet:
        if packet.haslayer(DNSQR):
            if packet[DNSQR].qname:
                IsolationForest.predictQueryLength([len(packet[DNSQR].qname)])

        elif packet.haslayer(DNSRR):
            if packet[DNSRR].rrname:
                IsolationForest.predictResponseLength([len(packet[DNSRR].rrname)])

def analysePacketFrequency(queryRateThreshold, responseRateThreshold, domainQueryPercentageThreshold, domainResponsePercentageThreshold):
    timeWindow = 60
    currentTime = time.time()
    queryRate = 0
    responseRate = 0
    domainQueryCount = {}
    domainResponseCount = {}
    queryIPAddressCount = {}
    # Simply just count how many times in a minute a query is made.
    for packet, timeStamp in sniffedPackets:
        if currentTime - timeStamp <= timeWindow:

            if DNS in packet:

                if packet.haslayer(DNSQR):
                    queryRate += 1

                    if packet[DNSQR].qname:
                        queryDomain = packet[DNSQR].qname.decode()
                        domainQueryCount[queryDomain] = domainQueryCount.get(queryDomain, 0) + 1


                        IPAddressSource = packet[IP].src
                        queryIPAddressCount[IPAddressSource] = queryIPAddressCount.get(IPAddressSource, 0) + 1
                    else:
                        print("This packet has DNSQR but no query name!?")
                elif packet.haslayer(DNSRR):
                    responseRate += 1
                    if packet[DNSRR].rrname:
                        
                        responseDomain = packet[DNSRR].rrname.decode()
                        domainResponseCount[responseDomain] = domainResponseCount.get(responseDomain, 0) + 1

    if queryRate > queryRateThreshold:
        print("Potential query rate anomaly detected. Figuring out culprit...")
        for domain, count in domainQueryCount.items():

            percentage = (count / queryRate) * 100

            if percentage > domainQueryPercentageThreshold:
                print(f"Domain {domain} exceeds query percentage threshold: {percentage}%")
        
    

    if responseRate > responseRateThreshold:
        print("Potential response rate anomaly detected. Figuring out culprit...")

        for domain, count in domainResponseCount.items():
            percentage = (count / responseRate) * 100

            if percentage > domainResponsePercentageThreshold:
                print(f"Domain {domain} exceeds response percentage threshold: {percentage}%")


def viewDNSPropertiesOfPackets(packet): # Could do length check
    functionName = inspect.stack()[0].function # Get the caller function. Just for printing
    
    if DNS in packet:
        packet = packet[DNS]
    try:
        # The following fields are fields we will scrutinise.
        print("DNS Query:", packet.qd.qname)
        print("DNS Query Type:", packet.qd.qtype)
        print("DNS Response:", packet.an.rdata)
        
        # The following will check if the domain name matches the ip address.
        # In scenarios where the packet has multiple IP addresses, we will ignore for now. (error is thrown)
        # TODO: Do an algorithm for detection for similarity in domain names
    except Exception as err:
        print(f"{functionName}(): Unexpected {err=}, {type(err)=}")
        pass # We ignore because the packet may not have anything required for checks

def viewDNSPacketsSniffed(packet):
    if DNS in packet and IP in packet:
        IPSource = removeTrailingDot(packet[IP].src)
        domainName = removeTrailingDot(packet[DNS].qd.qname.decode('utf-8'))
        print(f"DNS Query from {IPSource}: {domainName}")
        if verifyDNSLookups(domainName, IPSource):
            print("No discrepancy.")
        else:
            print("Discrepancy detected.")


def storePackets(packet):
    
    timestamp = time.time()
    if DNS in packet:
        sniffedPackets.append((packet, timestamp))

def forwardDNSLookup(domainName):
    forwardQuery = DNS(rd=1, qd=DNSQR(qname=domainName))
    # We query Google's DNS server
    DNSRequest = IP(dst='8.8.8.8') \
                    / UDP(dport=53) \
                    / forwardQuery
    forwardResponse = sr1(DNSRequest, verbose=0)
    result = forwardResponse[DNS].qd.qname.decode() # Question section; Query name of domain
    
    return removeTrailingDot(result)

def reverseDNSLookup(IPAddress):
    reverseQuery = DNS(rd=1, qd=DNSQR(qname=IPAddress))
    # We query Google's DNS server
    DNSRequest = IP(dst='8.8.8.8') \
                            / UDP(dport=53) \
                            / reverseQuery

    reverseResponse = sr1(DNSRequest, verbose=0)
    reverseDomain = reverseResponse[DNS].qd.qname.decode()
    return removeTrailingDot(reverseDomain)


def verifyDNSLookups(domainName, IPAddress):
    # Performs forward and reverse DNS lookups to check for consistency
    forwardDomain = forwardDNSLookup(domainName)
    reverseDomain = reverseDNSLookup(IPAddress)
    discrepancy = False

    if forwardDomain != domainName or reverseDomain != IPAddress:
        print(f"Unmatched domain and IP address for {IPAddress}!")
        discrepancy = True

    if forwardDomain != domainName:
        
        print(f"Forward lookup result: {forwardDomain}")
        print(f"Expected forward lookup result: {domainName}")
    
    if reverseDomain != IPAddress:
        
        print(f"Reverse lookup result: {reverseDomain}")
        print(f"Expected reverse lookup result: {IPAddress}")

    return True if not discrepancy else False


#verifyDNSLookups("pypi.org.","151.101.0.223.")
def removeTrailingDot(domainName):
    if domainName[-1] == ".":
        return domainName.rstrip(".")
    return domainName


#TODO: Set your threshold for these values!
queryRateThreshold = 100  
responseRateThreshold = 50
domainQueryPercentageThreshold = 0.3
domainResponsePercentageThreshold = 0.3

previousTimeAnalysis = time.time()
while True:
    sniff(filter="udp port 53", prn=storePackets, store=0, count = 5) # Remove count parameter to sniff forever
    #TODO: You should increase the count once you are confident the code works. Maybe to 10 or something.

    # At this line we already store the sniffed packets


    checkPackets(extractPacketsWithoutTimestamp(sniffedPackets))
    
    if time.time() - previousTimeAnalysis >= 60: # repeat the checks every 60 seconds.
        
        
        
        analysePacketFrequency(queryRateThreshold ,responseRateThreshold,domainQueryPercentageThreshold, domainResponsePercentageThreshold)
        previousTimeAnalysis = time.time()