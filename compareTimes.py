dotOneOutput = open('DOTONEoutput.txt', 'r')
googleOutput = open('GOOGLEoutput.txt', 'r')
normOutput = open('output.txt', 'r')

dotOneList = []
googleList = []
normList = []

for stuff in [(dotOneOutput, dotOneList), (googleOutput, googleList), (normOutput, normList)]:
    for line in stuff[0].readlines():
        words = line.split()
        if words[1] == 'FAIL':
            continue
        else:
            stuff[1].append(float(words[1]))

with open('DOTONEnumbers.txt', 'a') as dotOneFile:
    for num in dotOneList:
        print(num, file=dotOneFile)

with open('GOOGLEnumbers.txt', 'a') as googleFile:
    for num in googleList:
        print(num, file=googleFile)

with open('NORMnumbers.txt', 'a') as normFile:
    for num in normList:
        print(num, file=normFile)

print('DOTONE DNS')
print('average:', sum(dotOneList) / len(dotOneList), 'total success:', f'{len(dotOneList) / 5500 * 100}%')

print('GOOGLE DNS')
print('average:', sum(googleList) / len(googleList), 'total success:', f'{len(googleList) / 5500 * 100}%')

print('MY DNS')
print('average:', sum(normList) / len(normList), 'total success:', f'{len(normList) / 5500 * 100}%')
