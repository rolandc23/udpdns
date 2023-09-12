import socket
import json
import sys

validTypes = ['A', 'NS', 'CNAME', 'PTR', 'MX']

if __name__ == "__main__":
    qType = ''
    try:
        numArgs = len(sys.argv)
        if numArgs < 4:
            raise ValueError('ERROR: Invalid arguments\nUSAGE: python3 client.py resolver_ip resolver_port name [type=A] [timeout=5]')
        host = sys.argv[1]
        serverPort = int(sys.argv[2])
        domainName = sys.argv[3]
        if numArgs > 4:
            qType = sys.argv[4].upper()
            if qType not in validTypes: raise ValueError('ERROR: The query type you have requested is not supported')
        if numArgs > 5:
            timeout = float(sys.argv[5])
            if timeout <= 0: raise ValueError('ERROR: timeout must be greater than 0')
        else:
            timeout = 5
        clientPacket = {'domain': domainName, 'type': qType if qType else 'A', 'timeout': timeout}
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clientSocket.settimeout(timeout)
        clientSocket.sendto(json.dumps(clientPacket).encode('utf-8'), (host, serverPort))
        res, sAddr2 = clientSocket.recvfrom(4096)
        data = json.loads(res.decode('utf-8'))
    except socket.timeout:
        print('ERROR: Server has timed out')
        exit()
    except ValueError as v:
        print(v)
        exit()
    except WindowsError as w:
        print(w)
        exit()

    if 'ERROR' in data:
        print(f'ERROR: {data["ERROR"]}')
        exit()

    print('-->>Header<<-- ')
    print(f'flags: {data["Header"]["flags"]} id: {data["Header"]["id"]} QUERY: {data["Header"]["numQuestions"]}, ANSWER: {data["Header"]["numAnswers"]}, AUTHORITY: {data["Header"]["numAuthorities"]}, ADDITIONAL: {data["Header"]["numAdditionals"]}')

    print(';; QUESTION SECTION:')
    for q in data['Questions']:
        print(f'{q["name"]:<30} {q["class"]:<5} {q["type"]:<5}')

    print('\n;; ANSWER SECTION:')
    for answer in data['Answers']:
        print(f'{answer["name"]:<30} {answer["class"]:<5} {answer["type"]:<5} {answer["data"]}')

    print('\n;; AUTHORITY SECTION:')
    for authority in data['Authorities']:
        print(f'{authority["name"]:<30} {authority["class"]:<5} {authority["type"]:<5} {authority["data"]}')

    print('\n;; ADDITIONAL SECTION:')
    for additional in data['Additional']:
        print(f'{additional["name"]:<30} {additional["class"]:<5} {additional["type"]:<5} {additional["data"]}')




    clientSocket.close()