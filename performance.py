import socket
import json
import time

file = open('retry.txt', 'r')

for url in file.readlines():
    data = {}
    try:
        clientPacket = {'domain': url[:-1], 'type': 'A', 'timeout': 10}
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clientSocket.settimeout(10)
        t1 = time.time() * 1000
        clientSocket.sendto(json.dumps(clientPacket).encode('utf-8'), ('127.0.0.1', 5300))
        res, sAddr2 = clientSocket.recvfrom(20000)
        data = json.loads(res.decode('utf-8'))
        t2 = time.time() * 1000
    except socket.timeout:
        print('ERROR: Server has timed out')
    except ValueError as v:
        print(v)

    if not data: res = 'FAIL'

    if data and'ERROR' in data:
        res = 'FAIL'
    else:
        res = t2 - t1
    with open("second.txt", "a") as f:
        print(f'{url[:-1]:<40} {res}', file=f)

    clientSocket.close()

