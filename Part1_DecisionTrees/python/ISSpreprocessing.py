import csv
import random
import copy

# Converts IP address string to integer
def convertIP(iP):
    # print("Converting")
    iPList = iP.split('.')

    return ((int(iPList[0]) * 16777216) + (int(iPList[1]) * 65536) + (int(iPList[2]) * 256) + int(iPList[3]))

# Split IP addresses, set numeric values to 0 if empty for that instance, attach label
def preprocess(traffic, label):

    removeRows = []
    
    for row in traffic:

        # Remove ARP because their addresses are weird
        if (str(row[4]) == 'ARP'):
            removeRows.append(row)
            continue
        
        # Remove rows with empty ports
        if (row[1] == ''):
            removeRows.append(row)
            continue
        if (row[3] == ''):
            removeRows.append(row)
            continue

        # Convert IPs to integers
        row[0] = convertIP(row[0])
        row[2] = convertIP(row[2])

        # Make TCP Length, UDP Length, and TCP Window Size 0 if there is none
        if (str(row[-2]) == ''):
            row[-2] = 0
        if (str(row[-3]) == ''):
            row[-3] = 0
        if (str(row[-4]) == ''):
            row[-4] = 0

        # Change empty HTTP Request Methods to None
        if (row[-1] == ''):
            row[-1] = 'None'

        # Append label for traffic
        row.append(label)

    traffic[:] = [row for row in traffic if row not in removeRows]

# Scales data based on minimum and maximum possible values to 0-1
def scaleData(traffic):

    protocols = []
    maxLength = 0
    maxTCPWindowSize = 0
    maxTCPLength = 0
    maxUDPLength = 0
    httpRequests = []
    
    for row in traffic:
        
        if row[4] not in protocols:
            protocols.append(row[4])
            
        if int(row[5]) > int(maxLength):
            maxLength = int(row[5])

        if int(row[6]) > int(maxTCPWindowSize):
            maxTCPWindowSize = int(row[6])

        if int(row[7]) > int(maxTCPLength):
            maxTCPLength = int(row[7])

        if int(row[8]) > int(maxUDPLength):
            maxUDPLength = int(row[8])

        if row[9] not in httpRequests:
            httpRequests.append(row[9])

    for row in traffic:
        
    # Range for Source IP address spots 0-4294967295, [0]
        row[0] = int(row[0]) / 4294967295

    # Range for Source Port 0-65536, [1]
        row[1] = int(row[1]) / 65536

    # Range for Destination IP Adress spots 0-4294967295, [2]
        row[2] = int(row[2]) / 4294967295

    # Range for Destination Port 0-65536, [3]
        row[3] = int(row[3]) / 65536

    # Protocol does not have numeric range, gonna have to grab list of protocals for ARFF file, [4]

    # Length get values from list, [5]
        row[5] = int(row[5]) / maxLength

    # TCP window size get values from list, [6]
        row[6] = int(row[6]) / maxTCPWindowSize

    # TCP Length get values from list, [7]
        row[7] = int(row[7]) / maxTCPLength

    # UDP Length get values from list, [8]
        row[8] = int(row[8]) / maxUDPLength

    # HTTP request method also not numeric, grab list for ARFF from list, [9]
    
    # Label don't need to scale this, [10]

    print("Protocols: " + str(protocols))
    print("Max Length: " + str(maxLength))
    print("Max TCP Window Size: " + str(maxTCPWindowSize))
    print("Max TCP Length: " + str(maxTCPLength))
    print("Max UDP Length: " + str(maxUDPLength))
    print("HTTP Requests: " + str(httpRequests))

#### Normal Traffic Section

normalTraffic = []
with open("normalTraffic.csv") as csvfile:
    readCSV = csv.reader(csvfile, delimiter=',')
    for row in readCSV:
        normalTraffic.append(row)

# Remove attribute label row, delete print part later
normalTraffic.pop(0)

# Preprocess Step 1
normalTraffic[0]
preprocess(normalTraffic, "Normal")
normalTraffic[0]

#### Attack Traffic 1 - JexBoss Exploit Section

attackTraffic1 = []
with open("attackTraffic1.csv") as csvfile:
    readCSV = csv.reader(csvfile, delimiter=',')
    for row in readCSV:
        attackTraffic1.append(row)

# Remove attribute label row
attackTraffic1.pop(0)

# Preprocess Step 1
preprocess(attackTraffic1, "JexBossExploit")


#### Attack Traffic 2 - Neutrino Exploit Section

attackTraffic2 = []
with open("attackTraffic2.csv") as csvfile:
    readCSV = csv.reader(csvfile, delimiter=',')
    for row in readCSV:
        attackTraffic2.append(row)

# Remove attribute label row
attackTraffic2.pop(0)

# Preprocess Step 1
preprocess(attackTraffic2, "NeutrinoExploit")


#### Attack Traffic 3 - W32/Sdbot Infected Section

attackTraffic3 = []
with open("attackTraffic3.csv") as csvfile:
    readCSV = csv.reader(csvfile, delimiter=',')
    for row in readCSV:
        attackTraffic3.append(row)

# Remove attribute label row
attackTraffic3.pop(0)

# Preprocess Step 1
preprocess(attackTraffic3, "W32/SdbotInfected")


#### Attack Traffic 4 - Packet Injection Section

attackTraffic4 = []
with open("attackTraffic4.csv") as csvfile:
    readCSV = csv.reader(csvfile, delimiter=',')
    for row in readCSV:
        attackTraffic4.append(row)

# Remove attribute label row
attackTraffic4.pop(0)

# Preprocess Step 1
preprocess(attackTraffic4, "PacketInjection")

    
#### Attack Traffic 5 - Malspam Section

attackTraffic5 = []
with open("attackTraffic5.csv") as csvfile:
    readCSV = csv.reader(csvfile, delimiter=',')
    for row in readCSV:
        attackTraffic5.append(row)

# Remove attribute label row
attackTraffic5.pop(0)

# Preprocess Step 1
preprocess(attackTraffic5, "Malspam")


# Merge Traffic for signature detection
allTrafficSig = normalTraffic + attackTraffic1 + attackTraffic2 + attackTraffic3 + attackTraffic4 + attackTraffic5


# Preprocess Step 
scaleData(allTrafficSig)


# Copy data for anomaly detection
allTrafficAn = copy.deepcopy(allTrafficSig)

# Relabel attacks for anomaly detection
for row in allTrafficAn:
    if (row[-1] != "Normal"):
        row[-1] = "Abnormal"

random.shuffle(allTrafficSig)
random.shuffle(allTrafficAn)

with open('allTrafficSig.csv', mode = 'w', newline = '') as sigFile:
    
    sigWriter = csv.writer(sigFile, delimiter=',')

    for row in allTrafficSig:
        sigWriter.writerow(row)

with open('allTrafficAn.csv', mode = 'w', newline = '') as anFile:
    
    anWriter = csv.writer(anFile, delimiter=',')

    for row in allTrafficAn:
        anWriter.writerow(row)

