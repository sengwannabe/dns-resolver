#!/usr/bin/env python3
from helperfunctions import *
import socket
import sys
import re
import threading

def parseRDATA(stype, data):
    """helper function returns the rdata of a specified type from an RR section"""
    rdata = None
    for string in data:
        if f'TYPE={stype}' in string:
            matchObject = re.search(r'RDATA=(.*)', string)
            rdata = matchObject.group(1).rstrip()
            break
    return rdata

def parseTYPE(name, data):
    """helper function returns the type of a specified name from an RR section"""
    type = None
    for string in data:
        if name in string:
            matchObject = re.search(r'TYPE=(\w*)', string)
            type = matchObject.group(1).rstrip()
            break
    return type

def getRCODEValue(RCODE):
    """helper function translates RCODE string to code number"""
    matchObject = re.search(r'code (\d):?', RCODE)
    rcodeValue = matchObject.group(1)
    return int(rcodeValue)

def resolve(socketServer, addressClient, roots, inputQuery, timeout):
    """function carries out resolver action on given query"""
    parsedQuery, errorFlag = parseMessage(inputQuery)

    STYPE = parsedQuery['qtype']
    targetSNAME = parsedQuery['qname']
    currentTargetServer = None
    response = None

    i = 0
    while i < len(roots):
        currentSNAME = targetSNAME
        currentTargetServer = roots[i]
        while 1:
            timeoutFlag = False
            errorFlag = False
            query, nameErrorFlag = createQuery(STYPE, currentSNAME)
            # nameErrorFlag already checked at client side, all ns in resolver is valid
            response = sendQuery(query, currentTargetServer, 53, timeout)
            if checkTimeoutError(response):
                # resolver timeout, hence exhaust other root server
                timeoutFlag = True
                i += 1
                break

            parsedResponse, errorFlag = parseMessage(response)
            if errorFlag == True:
                rcodeValue = getRCODEValue(parsedResponse)
                if rcodeValue == 2 or rcodeValue == 5:
                    # server failure, hence exhaust other root servers
                    i += 1
                    break
                else: 
                    # returned error code to client to parse, sys.exit(1) here at resolver
                    socketServer.sendto(response, addressClient)
                    sys.exit(1)

            if parsedResponse['answers'] != None and parsedResponse['answers'] != [None]:
                # answer exist, if type is CNAME, change SNAME and start search again from root
                strippedCurrentSNAME = currentSNAME.rstrip('.')
                parsedResponseType = getTypeValue(parseTYPE(strippedCurrentSNAME, parsedResponse['answers']))
                if parsedResponseType == STYPE:
                    return socketServer.sendto(response, addressClient)
                elif parsedResponseType == getTypeValue('CNAME'):
                    currentSNAME = parseRDATA('CNAME', parsedResponse['answers'])
                    currentTargetServer = roots[i]
            elif parsedResponse['additionals'] != None and parsedResponse['additionals'] != [None]:
                # additionals exist, find type A nameservers with IP address and set as new IP
                currentTargetServer = parseRDATA('A', parsedResponse['additionals'])
            elif parsedResponse['authorities'] != None and parsedResponse['authorities'] != [None]:
                # authorities only exist
                currentSNAME = parseRDATA('NS', parsedResponse['authorities'])
                currentTargetServer = roots[i]
    
    # broke out of root while loop, all root servers been exhausted, hence return either timeout or server failure to client
    if timeoutFlag == True or errorFlag == True:
        socketServer.sendto(response, addressClient)
    sys.exit(1)

if __name__ == '__main__':
    # error handling for incorrect number of argument
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print('Error: invalid arguments')
        print('Usage: resolver port [timeout = 5]')
        sys.exit(1)

    #Define connection (socket) parameters
    serverPort = int(sys.argv[1])
    timeout = 5

    if len(sys.argv) == 3:
        timeout = int(sys.argv[2])

    # error handling for incorrect port number
    if serverPort < 2**10 or serverPort >= 2**16:
        print('Error: invalid port number')
        sys.exit(1)

    # collect IP of all roots
    rootServers = []
    with open('named.root', 'r') as rootFile:
        for line in rootFile:
            parts = re.split(r'\s', line)
            parts = list(filter(None, parts))
            if 'A' in parts:
                rootServers.append(parts[3])

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverSocket.bind(('127.0.0.1', serverPort))

    while 1:
        query, clientAddress = serverSocket.recvfrom(2048)
        thread = threading.Thread(target=resolve, args=(serverSocket, clientAddress, rootServers, query, timeout))
        thread.start()

    serverSocket.close()
    sys.exit(0)
