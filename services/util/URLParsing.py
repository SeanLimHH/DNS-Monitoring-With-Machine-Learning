import re
import validators

def isValidIPAddress(IPAddress):
    # Pattern: https://regex101.com/r/ky1g6s/1
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions/Cheatsheet#character_classes

    pattern = re.compile(r'^[0-9]+.+[0-9]$')
    match = re.match(pattern, IPAddress)
    if match is not None:
        return True
    else:
        return False

def isValidDomain(string):
    
    if validators.domain(string):
        return True
    else:
        return False

def isValidURL(string):
    # Pattern: https://regex101.com/r/LOQEXz/2
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions/Cheatsheet#character_classes

    pattern = re.compile(r'^https?://www(.[a-z0-9]+)+')
    match = re.match(pattern, string)
    if match is not None:
        return True
    else:
        return False

def isLocalHost(IPAddress):
    if IPAddress == "127.0.0.1" or "localhost" in IPAddress:
        return True
    return False

def getOnlyNumbersOrDot(IPAddress):
    match = re.match(r'^[\d.]+$', IPAddress)
    return match is not None
