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

    for group in cleanedGroupedRecords:
        print("\n\nRecord Name:",group['Record Name'])
        for record in group['Records']:
            print(record)

    print("End of clean DNS record")
    return cleanedGroupedRecords



def clusterIntoGroups(listOfLists, matchingStringToGroup):
    groups = []

    for element in listOfLists:
        key, values = element[0], element[1:]

        if key == matchingStringToGroup:
            # Matches 'Record Name'
            currentRecordName = values[0]
            # Then we return the next existing group with record name if it exists.
            currentGroup = next((group for group in groups if group[matchingStringToGroup] == currentRecordName), None)

            # This means the group is first; no such record name exists yet
            if currentGroup is None:
                currentGroup = {matchingStringToGroup: currentRecordName, 'Records': []}
                
                groups.append(currentGroup)

        else:

            if len(values) == 1:
                values = values[0]

            currentGroup['Records'].append((key, values))

    return groups

