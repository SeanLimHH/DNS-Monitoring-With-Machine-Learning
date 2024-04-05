import pandas as pd
TUNNELING_DATA_PATH = 'dataset/binary/dtqbc-b-train.csv'

CSIRTGadgets_DATA_PATH_WHITELIST = 'dataset/whitelist.txt'
CSIRTGadgets_DATA_PATH_BLACKLIST = 'dataset/blacklist.txt'



def getTunnelingData():
    return pd.read_csv(TUNNELING_DATA_PATH)

def getQueryNameLengthNormalTunnelingData():
    df = getTunnelingData()
    df = df[df['label'] == 0] # We only want "non-malicious dataset"
    return df['qd_qname_len'].tolist()

def getResourceRecordNameLengthNormalTunnelingData():
    df = getTunnelingData()
    df = df[df['label'] == 0] # We only want "non-malicious dataset"
    return df['an_rrname_len'].tolist()

def getWhiteAndBlacklistTunnelingData():
    whiteListedDomains = []
    blackListedDomains = []
    df = getTunnelingData()
    df = df.iloc[:, :2]
    for index, row in df.iterrows():
        isTunnelling, domainName = row.tolist()
        if isTunnelling == 0:
            whiteListedDomains.append(domainName)
        else:
            blackListedDomains.append(domainName)

    return whiteListedDomains, blackListedDomains

def getWhiteAndBlacklistCSIRTGadgets():
    
    whiteListedDomains = []
    blackListedDomains = []
    with open(CSIRTGadgets_DATA_PATH_WHITELIST,'r') as file:
        for line in file:
            whiteListedDomains.append(line)
    with open(CSIRTGadgets_DATA_PATH_BLACKLIST,'r') as file:
        for line in file:
            blackListedDomains.append(line)
    return whiteListedDomains, blackListedDomains


def getWhiteBlackListDataset():
    whiteListAll = []
    blackListAll = []

    whiteList, blackList = getWhiteAndBlacklistTunnelingData()
    whiteListAll += whiteList
    blackListAll += blackList

    whiteList, blackList = getWhiteAndBlacklistCSIRTGadgets()
    whiteListAll += whiteList
    blackListAll += blackList


    return whiteListAll, blackListAll


def getQueryResponseAndLengthDataset():
    df = getTunnelingData()
    df['label'] = df['label'].apply(lambda x: 1 if x != 0 else x)
    labels = df['label'].tolist()
    features = df[['qd_qtype', 'qd_qname_len', 'ar_type', 'ar_rdata_len']].values.tolist()
    return labels, features