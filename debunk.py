file = open('DOTONEoutput.txt', 'r')
retry = []
fail = []

for line in file.readlines():
    words = line.split()
    if words[1] == 'FAIL':
        fail.append(words[0])
    elif float(words[1]) < 0:
        retry.append(words[0])

with open('retry.txt', 'a') as f:
    for url in retry:
        print(url, file=f)

with open('DOTONEfail.txt', 'a') as g:
    for url in fail:
        print(url, file=g)