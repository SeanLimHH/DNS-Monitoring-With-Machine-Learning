import re
def splitTextByHyphens(text):
    return [part for part in re.split(r'-+', text)]


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


def cleanText(text):
    # Remove away the tabs
    cleanedText = re.sub(' ', '', text)
    # Reduce the new lines to one new line
    cleanedText = re.sub(r'\n+', '\n', text)
    cleanedText = cleanedText.strip()
    return cleanedText
