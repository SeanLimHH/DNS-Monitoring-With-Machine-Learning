def getEnvironmentVariable(key):
    with open('.env', 'r') as file:
        environmentVariables = file.readlines()
        environmentVariablesDictionary = {}
    for line in environmentVariables:
        key, value = line.strip().split('=')
        environmentVariablesDictionary[key] = value
    return environmentVariablesDictionary[key]