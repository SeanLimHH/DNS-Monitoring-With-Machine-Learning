def getEnvironmentVariable(desiredKey):
    
    environmentVariablesDictionary = {}
    with open('.env', 'r') as file:
        environmentVariables = file.readlines()
        for line in environmentVariables:
            key, value = line.strip().split('=')
            environmentVariablesDictionary[key] = value

    return environmentVariablesDictionary[desiredKey]