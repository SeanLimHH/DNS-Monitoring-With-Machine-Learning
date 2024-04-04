from scapy.all import sniff, DNS, IP, DNSQR, UDP, sr1, ls
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

        if suspicious == True:
            print("Suspicious:", ls(DNSPacket))

        sniffedPackets.append(packet)
sniff(filter="udp port 53", prn=queryResponseCheck, store=0, count=10)