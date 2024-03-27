import re

def splitTextByHyphens(text):
    return [part for part in re.split(r'-+', text)]

def cleanDNSRecords(records):

    noWhiteSpaceOnlyPropertiesRecords = {}
    cleanedRecords = []
    for recordPropertiesKeyValue in records:
        currentRecordName = ''
        recordPropertiesKeyValue = recordPropertiesKeyValue.split("\n")
        recordPropertiesKeyValue = [item.strip() for item in recordPropertiesKeyValue if item.strip()]
        recordPropertiesKeyValue = [item.split(':') if ':' in item else None for item in recordPropertiesKeyValue]
        recordPropertiesKeyValue = [item for item in recordPropertiesKeyValue if item is not None]
        for recordPropertyKeyValue in recordPropertiesKeyValue:
            recordPropertyKeyValue[0] = re.sub(r' \.+', '', recordPropertyKeyValue[0]).strip()
            recordPropertyKeyValue[1] = recordPropertyKeyValue[1].strip()
            cleanedRecords.append(recordPropertyKeyValue)


    cleanedGroupedRecords = clusterIntoGroups(cleanedRecords,'Record Name')

    for record in cleanedRecords:
        print(record)
    for group in cleanedGroupedRecords:
        print("\n\n\nGroup:",group)
        for record in group['Records']:
            print(record)

    print("End of clean DNS record")
    return cleanedGroupedRecords



def clusterIntoGroups(listOfLists, matchingStringToGroup):
    groups = []
    currentRecordName = None

    currentGroup = {}

    for element in listOfLists:
        key, values = element[0], element[1:]

        if key == matchingStringToGroup:

            currentRecordName = values[0]
            currentGroup = {'Record Name': currentRecordName, 'Records': []}

            groups.append(currentGroup)
        else:

            if len(values) == 1:

                values = values[0]

            if currentRecordName == currentGroup.get('Record Name'):
                currentGroup['Records'].append({key: values})

            else:
                currentGroup = {'Record Name': currentRecordName, 'Records': [{key: values}]}
                groups.append(currentGroup)

    return groups
