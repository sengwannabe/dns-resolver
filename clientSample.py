#!/usr/bin/env python3
from helperfunctions import *
import sys
import re

if __name__ == '__main__':
    # error handling for incorrect number of argument
    if len(sys.argv) < 4 or len(sys.argv) > 6:
        print('Error: invalid arguments')
        print('Usage: client resolver_ip resolver_port name [timeout = 5] [type = A]')
        sys.exit(1)

    #Define connection (socket) parameters
    resolverIP = sys.argv[1]
    resolverPort = int(sys.argv[2])
    queriedName = sys.argv[3]
    timeout = 5                             # default timeout value to be 5s
    queryType = 1                           # default type A has value 1

    if len(sys.argv) == 5:
        try:
            timeout = int(sys.argv[4])
        except ValueError:
            argument = sys.argv[4].upper()
            queryType = getTypeValue(argument)
    elif len(sys.argv) == 6:
            timeout = int(sys.argv[4])
            argument = sys.argv[5].upper()
            queryType = getTypeValue(argument)

    # error handling for incorrect port number
    if resolverPort < 2**10 or resolverPort >= 2**16:
        print('Error: invalid port number')
        sys.exit(1)

    # error handling for incorrect IP address
    numbersIP = re.findall(r"[0-9]+", resolverIP)
    if len(numbersIP) != 4:
        print('Error: invalid IP')
        sys.exit(1)

    for number in (int(inputNumber) for inputNumber in numbersIP):
        if number < 0 or number > 255:
            print('Error: invalid IP')
            sys.exit(1)

    query, nameErrorFlag = createQuery(queryType, queriedName)
    if nameErrorFlag == True:
        # received name error, hence print error and exit
        print(query)
        sys.exit(1)
    resolverResponse = sendQuery(query, resolverIP, resolverPort, timeout)

    if checkTimeoutError(resolverResponse):
        # client timeout encountered
        print('Error: timeout failure')
        sys.exit(1)

    parsedResponse, errorFlag = parseMessage(resolverResponse)
    if errorFlag == True:
        # received error flag at resolver, hence print error and sys.exit(1)
        print(parsedResponse)
        sys.exit(1)

    output = "\n{0:<20}{1}\n".format('Query ID:', parsedResponse['id'])

    output += "{0:<20}{1}\n".format('Flag:', bin(parsedResponse['flag'])[2:])
    if parsedResponse['aa']:
        aaFlag = True
    else:
        aaFlag = False

    output += "{0:<20}{1}\n".format('Is authoritative:', aaFlag)
    if parsedResponse['tc']:
        tcFlag = True
    else:
        tcFlag = False

    output += "{0:<20}{1}\n".format('Is truncated:', tcFlag)
    output += "{0:<20}{1}\n".format('Questions:', parsedResponse['qdcount'])
    output += "{0:<20}{1}\n".format('Answers:', parsedResponse['ancount'])
    output += "{0:<20}{1}\n".format('Authorities:', parsedResponse['nscount'])
    output += "{0:<20}{1}\n".format('Additionals:', parsedResponse['arcount']) + '\n'
    output += ';; QUESTION SECTION:\n'
    output += "{0:<25}{1:<5}{2:<5}\n".format(queriedName, 'IN', getTypeString(parsedResponse['qtype'])) + '\n'
    
    if parsedResponse['answers'] != None and parsedResponse['answers'] != [None]:
        output += ';; ANSWER SECTION:\n'
        for answer in parsedResponse['answers']:
            output += answer + '\n'
        output += '\n'
    
    if parsedResponse['authorities'] != None and parsedResponse['authorities'] != [None]:
        output += ';; AUTHORITY SECTION:\n'
        for authority in parsedResponse['authorities']:
            output += authority + '\n'
        output += '\n'

    if parsedResponse['additionals'] != None and parsedResponse['additionals'] != [None]:
        output += ';; ADDITIONAL SECTION:\n'
        for additional in parsedResponse['additionals']:
            output += additional + '\n'
        output += '\n'

    print(output)

    sys.exit(0)
