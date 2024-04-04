from scapy.all import sniff, DNS, IP, DNSQR, UDP, sr1, ls
import socket



packetsSniffed = []

def viewDNSPropertiesOfPackets(packetsList): # Could do length check
    for packet in packetsList:
        DNSProperties = packet[DNS]
        try:
            print("DNS ID:", DNSProperties.id)
            print("DNS Query:", DNSProperties.qd.qname)
            print("DNS Query Type:", DNSProperties.qd.qtype)
            print("DNS Response:", DNSProperties.an.rdata)
            print("Packet length:", len(packet))
        except:
            pass # We ignore because the packet may not have anything

def viewDNSPacketsSniffed(packet):
    if packet.haslayer(DNS) and packet.haslayer(IP):
        IPSource = removeTrailingDot(packet[IP].src)
        domainName = removeTrailingDot(packet[DNS].qd.qname.decode('utf-8'))
        print(f"DNS Query from {IPSource}: {domainName}")
        if verifyDNSLookups(domainName, IPSource):
            print("No discrepancy.")
        else:
            print("Discrepancy detected.")
        packetsSniffed.append(packet)

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
sniff(filter="udp port 53", prn=viewDNSPacketsSniffed, store=0, count = 10) # Remove count parameter to sniff forever

viewDNSPropertiesOfPackets(packetsSniffed)