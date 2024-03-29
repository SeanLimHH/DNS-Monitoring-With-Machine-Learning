def getAllIPAddresses(domainIPMap):
    return [IPAddress for IPAddressList in domainIPMap.values() for IPAddress in IPAddressList]


def getAllDomains(domainIPMap):
    return list(domainIPMap.keys())

