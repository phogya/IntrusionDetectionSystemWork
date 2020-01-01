baseString = 'alert tcp any :1134 -> 0.0.0.0/1 :5490 (msg: "Abnormal"; sid:1000044;)'

sIPRange = [
    'any'
    ]

dIPRange = [
    '192.168.8.199/32',
    '192.168.8.200/29',
    '192.168.8.208/28',
    '192.168.8.224/27',
    '192.168.9.0/24',
    '192.168.10.0/23',
    '192.168.12.0/22',
    '192.168.16.0/20',
    '192.168.32.0/19',
    '192.168.64.0/18',
    '192.168.128.0/17',
    '192.169.0.0/16',
    '192.170.0.0/15',
    '192.172.0.0/14',
    '192.176.0.0/12',
    '192.192.0.0/10',
    '193.0.0.0/8',
    '194.0.0.0/7',
    '196.0.0.0/6',
    '200.0.0.0/5',
    '208.0.0.0/4',
    '224.0.0.0/3'
    ]

combined = []
sid = 1007873

srcPort = "any"
destPort = "55480:"


for i in range(0, len(sIPRange)):
    for j in range(0, len(dIPRange)):

        current = baseString.split()
        current[2] = sIPRange[i]
        current[3] = srcPort
        current[5] = dIPRange[j]
        current[6] = destPort
        current[-1] = "sid:" + str(sid) + ";)"
        sid += 1
        combined.append(current)

s = " "
for item in combined:
    print(s.join(item))
               
 
