from scapy.all import sniff, DNS, IP, DNSQR, UDP, sr1, ls
import socket

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
        queryResponseCheck(packet)

        viewDNSPropertiesOfPackets(packet)

commonDNSQueryTypes = [1, 28, 5, 12, 2, 15, 6, 16]
commonDNSReturnCodes = [0, 2, 3, 5]
sniffedPackets = []
def queryResponseCheck(packet):
    print("Packet is being processed for query check...")
    suspicious = False
    if DNS in packet:
        DNSPacket = packet[DNS]
        if DNSPacket.qd.qtype not in commonDNSQueryTypes:
            print(f"Uncommon query type detected: {DNSPacket.qd.qtype}")
            suspicious = True
        if DNSPacket.rcode not in commonDNSReturnCodes:
            print(f"Unusual response code detected: {DNSPacket.rcode}")
            suspicious = True



def viewDNSPropertiesOfPackets(packet): # Could do length check
    if DNS in packet:
        packet = packet[DNS]
    try:
        # The following fields are fields we will scrutinise.
        print("DNS Query:", packet.qd.qname)
        print("DNS Query Type:", packet.qd.qtype)
        print("DNS Response:", packet.an.rdata)
        print("Packet length:", len(packet))

        # The following will check if the domain name matches the ip address.
        # In scenarios where the packet has multiple IP addresses, we will ignore for now. (error is thrown)
        # TODO: Do an algorithm for detection for similarity in domain names
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
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
    sniffedPackets.append(packet)

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
sniff(filter="udp port 53", prn=storePackets, store=0, count = 10) # Remove count parameter to sniff forever


# Here we already store the sniffed packets


checkPackets(sniffedPackets)