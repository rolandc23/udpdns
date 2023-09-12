dotOneFail = open('DOTONEfail.txt', 'r')
googleFail = open('GOOGLEfail.txt', 'r')
normFail = open('fail.txt', 'r')

dotOneList = []
googleList = []
normList = []

for stuff in [(dotOneFail, dotOneList), (googleFail, googleList), (normFail, normList)]:
    for fails in stuff[0].readlines():
        stuff[1].append(fails[:-1])

errorList = []
for record in dotOneList:
    if record in googleList and record in normList:
        errorList.append(record)

# print(errorList)
# print(len(errorList))

# with open('errorList.txt', 'a') as f:
#     for url in errorList:
#         print(url, file=f)