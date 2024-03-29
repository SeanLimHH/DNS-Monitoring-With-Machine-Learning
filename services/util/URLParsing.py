import re

def checkIfValidIPAddress(IPAddress):
    # Pattern: https://regex101.com/r/ky1g6s/1
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions/Cheatsheet#character_classes

    pattern = re.compile(r'^[0-9]+.+[0-9]$')
    match = re.match(pattern, IPAddress)
    if match is not None:
        return match
    else:
        raise Exception("IP address is invalid")

def checkIfValidDomain(string):
    # Pattern: https://regex101.com/r/8j1ZNV/1
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions/Cheatsheet#character_classes

    pattern = re.compile(r'^[A-z0-9]+.+[A-z0-9]$')
    match = re.match(pattern, IPAddress)
    if match is not None:
        return match
    else:
        raise Exception("Domain is invalid")

def checkIfValidURL(string):
    # Pattern: https://regex101.com/r/LOQEXz/2
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions/Cheatsheet#character_classes

    pattern = re.compile(r'^https?://www(.[a-z0-9]+)+')
    match = re.match(pattern, IPAddress)
    if match is not None:
        return match
    else:
        raise Exception("URL is invalid")

def isLocalHost(IPAddress):
    if IPAddress == "127.0.0.1" or "localhost" in IPAddress:
        return True
    return False

def getOnlyNumbersOrDot(IPAddress):
    match = re.match(r'^[\d.]+$', IPAddress)
    return match is not None
