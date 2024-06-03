#!/usr/bin/env python3
import socket
import sys
import re
import random

def createQuery(qType, requestName):
    """create query header section"""
    # format each flag corresponding RFC 1035 bits
    ID = int.to_bytes(random.randint(0, 65536), 2, byteorder='big')
    # no recursion flag
    flag = int.to_bytes(0, 2, byteorder='big')
    QDCOUNT = int.to_bytes(1, 2, byteorder='big')
    ANCOUNT = int.to_bytes(0, 2, byteorder='big')
    NSCOUNT = int.to_bytes(0, 2, byteorder='big')
    ARCOUNT = int.to_bytes(0, 2, byteorder='big')
    header = ID + flag + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    # create query question
    # format QNAME label length to 8 bits (octet), and corresponding label characters to 8 bits (octet)
    question = b''
    isNameError = False
    # strip trailing period to prevent label error
    strippedRequestName = requestName.rstrip('.')
    labels = re.split(r"[\.]", strippedRequestName)
    if '' in labels:
        # invalid domain name cannot be searched
        isNameError = True
        return getError(requestName, 3), isNameError

    for label in labels:
        labelLength = int.to_bytes(len(label), 1, byteorder='big')
        question += labelLength
        question += label.encode('utf-8')
    # domain name terminates with zero length octet
    question += int.to_bytes(0, 1, byteorder='big')
    # create and add QTYPE
    QTYPE = int.to_bytes(qType, 2, byteorder='big')
    question += QTYPE
    # create and add QCLASS (always IN -> 1)
    QCLASS = int.to_bytes(1, 2, byteorder='big')
    question += QCLASS

    return header + question, isNameError

def sendQuery(message, IP, Port, timeoutValue):
    """helper function sends message through inputted IP and Port with timeout"""
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.sendto(message, (IP, Port))
    clientSocket.settimeout(timeoutValue)
    message = None
    try:
        answer, serverAddress = clientSocket.recvfrom(2048)
        message = answer
    except socket.timeout:
        return 'Error: timeout failure'.encode('utf-8')
    # Close the socket
    clientSocket.close()

    return message

def checkTimeoutError(message):
    """helper function decodes message if it matches 'Error: timeout failure'"""
    try:
        decodedMessage = message.decode('utf-8')
        if decodedMessage == 'Error: timeout failure':
            return 1
        else:
            return 0
    except UnicodeDecodeError:
        return 0

def readName(inputIndex, response):
    """get variable length name, returns list containing successive response index and name"""
    labels = []
    index = inputIndex
    compressedFlag = False
    # end domain name search when reached zero length octet
    while response[index:index + 1] != b'\x00':
        byte = int.from_bytes(response[index:index + 1], byteorder='big') & 0xc0
        if byte == 0xc0:
            compressedFlag = True
            # RR name is compressed at next byte value offset
            offset = int.from_bytes(response[index + 1:index + 2], byteorder='big')
            NAME = readName(offset, response)[1]
            labels.append(NAME)
            # count index by 2 to read next byte after offset
            index += 2
            break
        else:
            # no terminating octet or compressed message
            labelLength = int.from_bytes(response[index:index + 1], byteorder='big')
            # print(f'labelLength = {labelLength}')
            # print(f'label to decode = {response[index + 1:index + 1 + labelLength]}')
            label = response[index + 1:index + 1 + labelLength].decode('utf-8')
            labels.append(label)
            index += labelLength + 1
    if compressedFlag == False:
        # if not compressed, count index next byte after terminating zero length octet
        index += 1
    # join labels by separating period
    return index, '.'.join(labels)

def getTypeString(inputType):
    """helper function returns corresponding type string from value, if input unaccepted, return 'error'"""
    if inputType == 1:
        return 'A'
    elif inputType == 2:
        return 'NS'
    elif inputType == 5:
        return 'CNAME'
    elif inputType == 12:
        return 'PTR'
    elif inputType == 15:
        return 'MX'
    else:
        return 'error'

def getTypeValue(inputType):
    """helper function returns corresponding type value from string, if input unaccepted, return 'error'"""
    if inputType == 'A':
        return 1
    elif inputType == 'NS':
        return 2
    elif inputType == 'CNAME':
        return 5
    elif inputType == 'PTR':
        return 12
    elif inputType == 'MX':
        return 15
    else:
        return 'error'

def readRDATA(length, inputType, RDATA, response):
    """helper function gets RDATA type and length-specified segment as string"""
    labels = []
    i = 0
    while i < length:
        byte = int.from_bytes(RDATA[i:i + 1], byteorder='big') & 0xc0
        if inputType == 'A':
            labels.append(str(int.from_bytes(RDATA[i:i + 1], byteorder='big')))
            i += 1
        else:
            if byte == 0xc0:
                # label is compressed at next byte value offset
                offset = int.from_bytes(RDATA[i + 1:i + 2], byteorder='big')
                NAME = readName(offset, response)[1]
                labels.append(NAME)
                i += 1
            else:
                labelLength = int.from_bytes(RDATA[i:i + 1], byteorder='big')
                label = RDATA[i + 1:i + 1 + labelLength].decode('utf-8')
                labels.append(label)
                i += labelLength + 1
    # join RDATA labels by separating period
    return '.'.join(labels)

def readRRFormat(inputIndex, response):
    """helper function produces list containing RR format specified keys"""
    # start at RR name, readName to get RR name
    inputIndex, NAME = readName(inputIndex, response)

    # read RR type
    typeValue = int.from_bytes(response[inputIndex:inputIndex + 2], byteorder='big')
    # if type is not of A, MX, CNAME or PTR, index to successive RR and return None
    if (TYPE := getTypeString(typeValue)) == 'error':
        # caught error, hence incorrect type
        inputIndex += 8
        # read RDLENGTH
        RDLENGTH = int.from_bytes(response[inputIndex:inputIndex + 2], byteorder='big')
        inputIndex += 2 + RDLENGTH

        return inputIndex, None
    else:
        # read RR type, skip over RR class
        TYPE = getTypeString(typeValue)
        inputIndex += 4
        # read RR TTL
        TTL = int.from_bytes(response[inputIndex:inputIndex + 4], byteorder='big')
        inputIndex += 4
        # read RDLENGTH and subsequent RDATA
        RDLENGTH = int.from_bytes(response[inputIndex:inputIndex + 2], byteorder='big')
        inputIndex += 2
        RDATA = response[inputIndex:inputIndex + RDLENGTH]
        RDATA = readRDATA(RDLENGTH, TYPE, RDATA, response)
        inputIndex += RDLENGTH

        return inputIndex, "{0:<25}TTL={1:<10}CLASS={2:<5}TYPE={3:<10}RDATA={4:>10}".format(NAME, TTL, 'IN', TYPE, RDATA)


def getError(domain, RCODE):
    """helper function attains the correct RCODE error string"""
    if RCODE == 1:
        return 'Error: code 1: server could not interpret query'
    elif RCODE == 2:
        return 'Error: code 2: server could not process query due to internal problem'
    elif RCODE == 3:
        return f'Error: code 3: server could not find {domain}'
    else:
        return f'Error: code {RCODE}'

def parseMessage(message):
    """helper function decodes and parses a RFC 1034 and 1035 formatted message, 
       returns error flag if produced error"""
    messageLabels = {
        'id': None,
        'flag': None,
        'qr': None,
        'aa': None,
        'tc': None,
        'rcode': None,
        'qdcount': None,
        'ancount': None,
        'nscount': None,
        'arcount': None,
        'qname': None,
        'qtype': None,
        'qclass': None,
        'answers': None,
        'authorities': None,
        'additionals': None
    }

    # read HEADER section
    ID = int.from_bytes(message[0:2], byteorder='big')
    messageLabels['id'] = ID

    flag = int.from_bytes(message[2:4], byteorder='big')
    messageLabels['flag'] = flag
    
    QR = (flag >> 15) & 0x1
    messageLabels['qr'] = QR
    AA = (flag >> 10) & 0x1
    messageLabels['aa'] = AA
    TC = (flag >> 9) & 0x1
    messageLabels['tc'] = TC
    RCODE = flag & 0xF
    messageLabels['rcode'] = RCODE

    # collect QD, AN, NS and AR counts
    QDCOUNT = int.from_bytes(message[4:6], byteorder='big')
    messageLabels['qdcount'] = QDCOUNT
    ANCOUNT = int.from_bytes(message[6:8], byteorder='big')
    messageLabels['ancount'] = ANCOUNT
    NSCOUNT = int.from_bytes(message[8:10], byteorder='big')
    messageLabels['nscount'] = NSCOUNT
    ARCOUNT = int.from_bytes(message[10:12], byteorder='big')
    messageLabels['arcount'] = ARCOUNT

    # parse QUESTION section
    # get QNAME
    index, SQNAME = readName(12, message)
    messageLabels['qname'] = SQNAME

    isError = False
    # check RCODE for errors with QNAME, if error return
    if RCODE != 0:
        isError = True
        return getError(SQNAME, RCODE), isError

    # get QTYPE
    QTYPE = int.from_bytes(message[index:index + 2], byteorder='big')
    index += 4
    messageLabels['qtype'] = QTYPE

    # QCLASS not changed, assumed as IN
    messageLabels['qclass'] = 'IN'

    answers = []
    # read ANSWERS section, if there is answers
    if ANCOUNT >= 1:
        for data in range(ANCOUNT):
            index, answer = readRRFormat(index, message) 
            answers.append(answer)
        messageLabels['answers'] = answers

    authorities = []
    # read AUTHORITIES section, if there is authorities
    if NSCOUNT >= 1:
        for data in range(NSCOUNT):
            index, authority = readRRFormat(index, message)
            authorities.append(authority)
        messageLabels['authorities'] = authorities

    additionals = []
    # read ADDITIONAL section, if there is additionals
    if ARCOUNT >= 1:
        for data in range(ARCOUNT):
            index, additional = readRRFormat(index, message)
            if additional == None:
                continue
            else:
                additionals.append(additional)
        messageLabels['additionals'] = additionals

    return messageLabels, isError
