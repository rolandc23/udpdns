import socket
import sys
from random import randint
import struct
import ipaddress
import json

QTYPE = {
    1: 'A',    
    2: 'NS',   
    5: 'CNAME',
    6: 'SOA',  
    12: 'PTR', 
    15: 'MX',  
    16: 'TXT', 
    28: 'AAAA',
    'A': 1,    
    'NS': 2,   
    'CNAME': 5,
    'SOA': 6,  
    'PTR': 12, 
    'MX': 15,  
    'TXT': 16, 
    'AAAA': 28,
}

CLASS = {
    1: 'IN',
    2: 'CS',
    3: 'CH',
    4: 'HS',
    'IN': 1,
    'CS': 2,
    'CH': 3,
    'HS': 4
}

QUESTION_OFFSET = 12
MAX_H = 65535

class Header:
    def __init__(self, id, flags, qdCount, anCount, nsCount, arCount):
        self.id = id 
        self.flags = flags
        self.qdCount = qdCount
        self.anCount = anCount
        self.nsCount = nsCount
        self.arCount = arCount

class Question:
    def __init__(self, qName, qType, qClass):
        self.qName = qName 
        self.qType = qType
        self.qClass = qClass

class RR:
    def __init__(self, rName, rType, rClass, rTTL, rDLength, rData):
        self.rName = rName 
        self.rType = rType
        self.rClass = rClass
        self.rTTL = rTTL
        self.rDLength = rDLength
        self.rData = rData

class Packet:
    def __init__(self, header, questions, answerRR, authorityRR, additionalRR):
        self.header = header 
        self.questions = questions
        self.answerRR = answerRR
        self.authorityRR = authorityRR
        self.additionalRR = additionalRR

rootServers = []

def getRootNameServers():
    global rootServers
    file = open('named.root', 'r')
    lines = file.readlines()
    for i in range(17, 90, 6):
        rootServers.append((lines[i].split()[3], 'additional'))
    
def encodeName(name):
    return b''.join([b'', ''.join(chr(len(label)) + label for label in name.split('.')).encode('utf8'), b'\x00'])

def decodeName(res, offset):
    name = []
    currOffset = offset
    while labelLength := res[currOffset: currOffset + 1][0]:
        currOffset += 1
        if labelLength & 0b1100_0000:
            name.append(decompressName(labelLength, res, currOffset))
            break
        else:
            name.append(res[currOffset: currOffset + labelLength].decode('utf-8'))
            currOffset += labelLength
    decodedName = '.'.join(name)
    currOffset += 1
    return decodedName, currOffset

def decompressName(length, res, offset):
    pointerByte = bytes([length & 0b0011_1111]) + res[offset: offset + 1]
    pointer = struct.unpack("!H", pointerByte)[0]
    result, _ = decodeName(res, pointer)
    return result

def makeQuery(domainName, queryType):
    encodedName = encodeName(domainName)
    header = Header(id = randint(0, MAX_H), qdCount = 1, flags = 0, anCount = 0, nsCount = 0, arCount = 0)
    question = Question(qName = encodedName, qType = QTYPE[queryType], qClass = CLASS['IN'])
    queryPacket = struct.pack('!HHHHHH', header.id, header.flags, header.qdCount, header.anCount, header.nsCount, header.arCount) + question.qName + struct.pack('!HH', question.qType, question.qClass)
    return queryPacket

def decodeQuestions(res, numQuestions):
    questions = []
    currOffset = QUESTION_OFFSET
    for _ in range(numQuestions):
        qName, offset = decodeName(res, currOffset)
        qType = int.from_bytes(res[offset: offset + 2], byteorder = 'big')
        qClass = int.from_bytes(res[offset + 2: offset + 4], byteorder = 'big')
        currOffset = offset + 4
        questions.append(Question(qName, qType, qClass))
    return questions, currOffset

def decodeRR(res, numRecord, offset):
    records = []
    currOffset = offset
    for _ in range(numRecord):
        rName, newOffset = decodeName(res, currOffset)
        rType = int.from_bytes(res[newOffset: newOffset + 2], byteorder = 'big')
        rClass = int.from_bytes(res[newOffset + 2: newOffset + 4], byteorder = 'big')
        rTTL = int.from_bytes(res[newOffset + 4: newOffset + 8], byteorder = 'big')
        rDataLength = int.from_bytes(res[newOffset + 8: newOffset + 10], byteorder = 'big')
        if rDataLength == 0: raise ValueError('DNS response is malformed, invalid, or of an unaccepted type')
        currOffset = newOffset + 10
        if rType in (QTYPE['NS'], QTYPE['CNAME'], QTYPE['PTR']):
            rData, newPos = decodeName(res, currOffset)
            currOffset = newPos
        elif rType == QTYPE['MX']:
            rData, newPos = decodeName(res, currOffset + 2)
            currOffset = newPos
        elif rType == QTYPE['AAAA']:
            if rDataLength != 16: raise ValueError('DNS response is malformed or invalid')
            rData = str(ipaddress.IPv6Address(res[currOffset: currOffset + 16]))
            currOffset += 16
        elif rType == QTYPE['A']:
            if rDataLength != 4: raise ValueError('DNS response is malformed or invalid')
            rData = '.'.join([str(byte) for byte in res[currOffset: currOffset + rDataLength]])
            currOffset += rDataLength
        else:
            rData = res[currOffset: currOffset + rDataLength]
            currOffset += rDataLength
        records.append(RR(rName, rType, rClass, rTTL, rDataLength, rData))
        
    return records, currOffset

def checkResponseCode(rc):
    if rc == 1:
       raise ValueError('ERROR: response contains formatting error')
    if rc == 2:
        raise ValueError('ERROR: Server failure')
    if rc == 3:
        raise ValueError('ERROR: Name Error')
    if rc == 4:
        raise ValueError('ERROR: Unsupported response code')
    if rc == 5:
        raise ValueError('ERROR: Refused') 
    return

def makeFlags(flags):
    headerFlags = []
    rcode = flags & 0b0000000000001111
    checkResponseCode(rcode)
    if bool(flags & 0b1000000000000000): headerFlags.append('qr')
    if bool(flags & 0b0000010000000000): headerFlags.append('aa')
    if bool(flags & 0b0000001000000000): headerFlags.append('tc')
    if bool(flags & 0b0000000100000000): headerFlags.append('rd')
    if bool(flags & 0b0000000010000000): headerFlags.append('ra')
    return ' '.join(headerFlags)

def decodeHeader(res):
    headerId = int.from_bytes(res[0:2], byteorder = 'big')
    flags = int.from_bytes(res[2:4], byteorder = 'big')
    headerFlags = makeFlags(flags)
    headerQs = int.from_bytes(res[4:6], byteorder = 'big')
    headerAns = int.from_bytes(res[6:8], byteorder = 'big')
    headerAuth = int.from_bytes(res[8:10], byteorder = 'big')
    headerAdd = int.from_bytes(res[10:12], byteorder = 'big')
    return Header(headerId, headerFlags, headerQs, headerAns, headerAuth, headerAdd)

def decodeResponse(res):
    header = decodeHeader(res)
    questions, qOffset = decodeQuestions(res, header.qdCount)
    answerRRs, ansOffset = decodeRR(res, header.anCount, qOffset)
    authorityRRs, authOffset = decodeRR(res, header.nsCount, ansOffset)
    additionalRRs, _ = decodeRR(res, header.arCount, authOffset)
    return Packet(header, questions, answerRRs, authorityRRs, additionalRRs)

def sendQuery(ns, domainName, type, timeout, last):
    query = makeQuery(domainName, type)
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.sendto(query, (ns, 53))
        conn.settimeout(timeout)
        data, _ = conn.recvfrom(4096)
    except socket.timeout:
        if last:
            raise TimeoutError('Timed out - Server failure or the address you have queried could not be resolved')
        print('Current server down, trying next')
        return None
    except socket.gaierror:
        if last:
            raise ValueError('ERROR: NS failed')
        print('Current server not working, trying next')
        return None
    response = decodeResponse(data)
    return response

def checkRecords(responsePacket, domainName):
    resList = []
    if responsePacket.answerRR:
        for answer in responsePacket.answerRR:
            resList.append((answer.rData, 'answer'))
    
    if responsePacket.authorityRR:        
        for authorityRR in responsePacket.authorityRR:
            if authorityRR.rType == QTYPE['NS']:
                resList.append((authorityRR.rData, 'authority'))

    if responsePacket.additionalRR:
        for additionalRR in responsePacket.additionalRR:
            if additionalRR.rType == QTYPE['A']:
                resList.append((additionalRR.rData, 'additional'))
    
    return resList if resList else [(f'Cannot resolve server {domainName}', 'error')]


def resolve(domainName, qType, timeout):
    global rootServers
    res = rootServers
    if qType == 'PTR':
        try:
            domainName = ipaddress.IPv4Address(domainName).reverse_pointer
        except ipaddress.AddressValueError:
            return extractError(f'The server {domainName} is not a valid PTR input, needs 4 octets like 12.1.2.3')
    domain = domainName
    currType = qType

    isLast = False

    while True:
        checkFailure = True
        for i, record in enumerate(res):
            if i == len(res) - 1: isLast = True
            case = record[1]
            if case == 'answer':
                print(f'Resolved - IP is {res[0][0]}')
                return extract(response)
            elif case == 'authority':
                nameServer = record[0].encode('utf-8')
            elif case == 'additional':
                nameServer = record[0]
            elif case == 'error':
                continue
            print(f"Querying {nameServer} for {domain}")
            if response := sendQuery(nameServer, domain, currType, timeout, isLast):
                res = checkRecords(response, domain)
                checkFailure = False
                break
        if checkFailure:
            return extractError(f'The server {domainName} cannot be resolved')
        
def extract(data):
    header = data.header
    questions = data.questions
    answerRR = data.answerRR
    authorities = data.authorityRR
    additionals = data.additionalRR
    
    resDict = {
        'Header': {
            'id': header.id,
            'flags': header.flags,
            'numQuestions': header.qdCount,
            'numAnswers': header.anCount,
            'numAuthorities': header.nsCount,
            'numAdditionals': header.arCount
        },
        'Questions': [{
            'name': question.qName,
            'type': QTYPE[question.qType],
            'class': CLASS[question.qClass],
        } for question in questions],
        'Answers': [{
            'name': answer.rName,
            'type': QTYPE[answer.rType],
            'class': CLASS[answer.rClass],
            'data': answer.rData
        } for answer in answerRR],
        'Authorities': [{
            'name': authority.rName,
            'type': QTYPE[authority.rType],
            'class': CLASS[authority.rClass],
            'data': authority.rData
        } for authority in authorities],
        'Additional': [{
            'name': additional.rName,
            'type': QTYPE[additional.rType],
            'class': CLASS[additional.rClass],
            'data': additional.rData
        } for additional in additionals],
    }

    return resDict

def extractError(res):
    return {'ERROR': res}

if __name__ == "__main__":
    try:
        if len(sys.argv) < 2: raise ValueError('ERROR: Specify port\nUSAGE: python3 resolver.py resolver_port [timeout=5]')
        port = int(sys.argv[1])
        if len(sys.argv) == 3:
            timeout = int(sys.argv[2])
            if timeout <= 0: raise ValueError('ERROR: timeout must be greater than 0')
        else:
            timeout = 1
        ip = '127.0.0.1'
        getRootNameServers()
    except ValueError as v:
        print(v)
        exit()

    while 1:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((ip, port))
            data, addr = sock.recvfrom(4096)
            info = json.loads(data.decode('utf-8'))
            finalAnswer = resolve(info['domain'], info['type'], timeout)
            sock.sendto(json.dumps(finalAnswer).encode('utf-8'), addr)
        except TimeoutError as t:
            print(t)
            sock.sendto(json.dumps(extractError(str(t))).encode('utf-8'), addr)
        except ValueError as v:
            print(v)
            sock.sendto(json.dumps(extractError(str(v))).encode('utf-8'), addr)
