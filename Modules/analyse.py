#!/usr/bin/python3
import os.path
import sys
import time

# import
from common import *


# Utilities
# ----------

def analyse_destroyTreatedFiles(folder, listofFiles2treat):  # unused
    # folder = "Capture_Files/"
    for i in listofFiles2treat:
        if os.path.exists(folder + i):
            os.remove(folder + i)


# 7 : get the CIPK table from a file
def analyse_getGhgPerKwhFromDatabase1():
    database_location = 'Database_Files/CIF.json'
    data = common_readFromJsonFile(database_location)
    return data


# 0 : get list of dump files to analyse
def analyse_getListOfFiles2Analyse(folder, action):
    # folder = "Capture_Files/"
    listOfFiles = os.listdir(folder)
    listofFiles2treat = []
    for i in listOfFiles:
        if i[:20] == "conso_macbook_tshark":
            listofFiles2treat.append(i)
    listofFiles2treat = sorted(listofFiles2treat)
    if action != 'a':
        listofFiles2treat.pop()
    return listofFiles2treat


# 0_version2 : get list of dump files to analyse
def analyse_getListOfFiles2Analyse1(folder):
    listOfFiles = os.listdir(folder)
    listofFiles2treat1 = []
    listofFiles2treat = []
    listofFiles2treat2 = []
    for i in listOfFiles:
        if i[:20] == "conso_macbook_tshark":
            listofFiles2treat1.append(i)
        for j in listofFiles2treat1:
            listofFiles2treat.append([j, time.ctime(os.path.getmtime(folder + j))])
    listofFiles2treat = sorted(listofFiles2treat)
    if listofFiles2treat:
        j = listofFiles2treat[0][1]
        k = []
        for i in listofFiles2treat:
            if i[1] >= j:
                j = i[1]
                k = i
        listofFiles2treat.remove(k)
    for i in listofFiles2treat:
        listofFiles2treat2.append(i[0])
    return listofFiles2treat2


# 2 : transform output text file into an array (so called global array)
def analyse_lines2table(fichier, separator):
    storage = []
    fic = open(fichier, 'r')
    lines = fic.readlines()
    fic.close()

    for i in range(len(lines)):  # lecture ligne par ligne
        tableOfFields = lines[i].split(separator)
        storage.append(tableOfFields)
    return storage


# 1 : filter the dump file in order to extract precise information on the packets (+ ipv6)
def analyse_capture2Output1(fileSaved, folder):
    listOfFiles = os.listdir(folder)
    file2beTreated = folder + "output" + str(len(listOfFiles))
    os.system(
        'tshark -r %s -T fields -e frame.len -e dns.qry.name -e dns.a \
            -e frame.time_relative -e ip.dst -e ip.src -e ipv6.dst -e ipv6.src -e ip.ttl \
             -E separator== > %s' % (fileSaved, file2beTreated))

    return file2beTreated


# 4 : get the framelength of all packets (gloabl array)
def analyse_totalFrameLength(array):
    total = 0
    for i in range(len(array)):
        total = total + int(array[i][0])  # framelength is associated with the index 0
    return total


# 5 : get the framelength of all packets (sub array, incoming / outgoing, gotten from the global array)
def analyse_totalFrameLength1(array):
    total = 0
    for i in array:
        total = total + int(i)
    return total


# 6.1 : extract dns reponse ip addr (string treatment)
def analyse_dnsAddrExtractor(string):
    tab = string.split(',')
    addr = tab[0]
    return addr


# 17.1 get percentage
def analyse_percentage(integer, total):
    answer = (integer / total) * 100.0
    return answer


# 17 : get ranking of traffic by total framelength value
def analyse_top10(theSizeMin, theSizeMax, totalSize, theTable):
    storage = {}
    totalBytesTop10 = 0

    for i in range(theSizeMin, theSizeMax):
        storage[i] = {}
        integer = theTable[i]['framelength']
        totalBytesTop10 += integer
        percent = analyse_percentage(integer, totalSize)  # @17.1
        domain = theTable[i]['QueryName']
        storage[i]['rang'] = i + 1
        storage[i]['domain'] = domain
        storage[i]['lengthOfFrame'] = integer
        storage[i]['percentage'] = percent
        if i < 10:
            print("N° %d \t=>\t%s \t%d bytes \tpercentage = %.2f \n " % (i + 1, domain, integer, percent))
    remainder = totalSize - totalBytesTop10
    if remainder > 0:
        percent1 = analyse_percentage(remainder, totalSize)  # @17.1
        size = len(storage)
        print("N° %d \t=>\t%s \t%d bytes \tpercentage = %.2f \n " % (theSizeMax + 1, "Others", remainder, percent1))
        storage[size] = {}
        storage[size]['rang'] = theSizeMax + 1
        storage[size]['domain'] = "Others"
        storage[size]['lengthOfFrame'] = remainder
        storage[size]['percentage'] = percent1
    return storage


# Take the information abbout all the connections after netstat from file
def info_netstat():
    with open('./Output_Files/Analyse/applications.txt', 'r') as f:
        lines = f.readlines()

    filtered_array = []
    for line in lines:
        filtered_array.append([elem.rstrip('\n') for elem in line.split(' ') if elem != ''])
    final_array = []

    for element_indx in range(0, len(filtered_array)):
        result_array = []
        #variants = ['LISTENING', 'ESTABLISHED', 'UDP']
        if ('LISTENING' in filtered_array[element_indx]) or ('ESTABLISHED' in filtered_array[element_indx]) or ('UDP' in filtered_array[element_indx]):
            try:
                #print(filtered_array[element_indx])
                if filtered_array[element_indx + 1][0].startswith('['):
                    app_name = filtered_array[element_indx + 1][0]
                    result_array.append(app_name.rstrip(']').lstrip('['))
                    # result_array.append(filtered_array[element_indx][2])
                    # result_array.append(filtered_array[element_indx][1])
                elif filtered_array[element_indx + 2][0].startswith('['):
                    app_name = filtered_array[element_indx + 2][0]
                    result_array.append(app_name.rstrip(']').lstrip('['))
                    # result_array.append(filtered_array[element_indx][2])
                    # result_array.append(filtered_array[element_indx][1])
                else:
                    app_name = ""
                    result_array.append(app_name)
            except IndexError:
                app_name = ""
                result_array.append(app_name)

            result_array.append(filtered_array[element_indx][2])
            result_array.append(filtered_array[element_indx][1])
            final_array.append(result_array)
    #print(final_array)
    return final_array


# 6 : revisiting the global array in order to extract the dns related info from dns packets
def analyse_getDnsQueries(tab, userIpAddr):
    dnsTable = []
    dnsTable.append(userIpAddr)

    tab.sort(key=lambda x: x[2], reverse=True)
    #
    final = []
    j = ''
    for k in range(len(tab)):
        ipsplit = tab[k][5].split(',')
        if len(ipsplit) >= 2:  # in order to avoid the following scenario : e.g 195.42.144.143,10.188.61.119
            tab[k][5] = ipsplit[0]
        if tab[k][2] != j:
            ipAddr = analyse_dnsAddrExtractor(tab[k][2])  # @6.1
            dnsTable.append(ipAddr)
            final.append({'QueryName': tab[k][1], 'IPAddress': ipAddr})
            j = tab[k][2]
        elif tab[k][1] == '' and ipsplit[0] not in dnsTable:
            if ipsplit[0] != '':
                ipAddr = ipsplit[0]
                dnsTable.append(ipAddr)
                final.append({'QueryName': ipAddr, 'IPAddress': ipAddr})
            elif tab[k][7] != '' and tab[k][5] == '':
                ipAddr = tab[k][7]
                if ipAddr not in dnsTable:
                    dnsTable.append(ipAddr)
                    final.append({'QueryName': ipAddr, 'IPAddress': ipAddr})
    #print(final)
    for j in range(len(final)):
        listOfFramesIn = []
        listOfFramesOut = []
        appsList = []
        if sys.platform != 'win32':  # find app and ips
            with open ('Output_Files/Analyse/applications.txt', 'r') as fic:
                lines = fic.readlines()

            for line in lines:
                line = line.split(" ")
                line = list(filter(None, line))

                if line[4] == 'IPv4':
                    try:
                        line[8] = line[8].split("->")
                        ipdst = line[8][0].split(":")
                        ipsrc = line[8][1].split(":")
                        appsList.append([line[0],ipdst[0],ipsrc[0]])
                    except:
                        ipdst = line[8][0].split(":")
                        appsList.append([line[0],ipdst,""])
                if line[4] == 'IPv6':
                    try:
                        line[8] = line[8].split("->")
                        ipdst = line[8][0].split("]:")
                        ipsrc = line[8][1].split("]:")
                        appsList.append([line[0],ipdst[0][1:],ipsrc[0][1:]])
                    except:
                        ipdst = line[8][0].split("]:")
                        appsList.append([line[0],ipdst[0][1:],""])
        else:  # Solution for Windows versions
            info_array = info_netstat()
            appsList = info_array

        for l in range(len(tab)):
            if tab[l][4] == final[j]['IPAddress'] or tab[l][6] == final[j]['IPAddress']:
                listOfFramesIn.append(tab[l][0])
            if tab[l][5] == final[j]['IPAddress'] or tab[l][7] == final[j]['IPAddress']:
                listOfFramesOut.append(tab[l][0])
        #print(final)
        for p in range(len(appsList)):
            #print('app', appsList[p])
            #print('final', final[j]['IPAddress'])
            if appsList[p][1].startswith(final[j]['IPAddress']) or appsList[p][2].startswith(final[j]['IPAddress']):
                if appsList[p][0] == "x-www-bro":
                    application = "browser" 
                else: 
                    application = appsList[p][0]
                break
            else:
                application = ""
        tmpTotalFrameLengthIn = analyse_totalFrameLength1(listOfFramesIn)  # @5
        tmpTotalFrameLengthOut = analyse_totalFrameLength1(listOfFramesOut)  # @5
        final[j]['application'] = application
        final[j]['framelength (in)'] = tmpTotalFrameLengthIn
        final[j]['framelength (out)'] = tmpTotalFrameLengthOut
        final[j]['framelength'] = tmpTotalFrameLengthIn + tmpTotalFrameLengthOut

    return final


# 18 : get a list of all ipv4 & ipv6 addresses along with their respective percentages
def analyse_ipType(tab, userIpAddr):
    ipv4 = []
    ipv6 = []
    for i in tab:
        if i[5].find('.') != -1 and i[5] != userIpAddr and i[5] not in ipv4:
            ipv4.append(i[5])
        elif i[7].find(':') != -1 and i[7] != userIpAddr and i[7] not in ipv6:
            ipv6.append(i[7])
    total = len(ipv4) + len(ipv6)
    ipv4_percentage = analyse_percentage(len(ipv4), total)
    ipv6_percentage = analyse_percentage(len(ipv6), total)
    return {"ipv4 addresses": ipv4, "ipv6 addresses": ipv6, "% ipv4 addresses": ipv4_percentage,
            "% ipv6 addresses": ipv6_percentage}


# calculations
# ------------

# Capture duration
# °°°°°°°°°°°°°°°°
# 10 : get duration of dump file
def analyse_capinfos_minutes(_path):
    # variables
    # ---------
    output_capinfos = "Output_Files/Analyse/output_capinfos0"
    capture_duration_in_minutes = 0
    if sys.platform == 'win32':  # solution for Windows
        capinfos_result = os.popen(
            'capinfos %s | find "Capture duration" ' % _path).read()
        with open(output_capinfos, 'w') as f:
            f.write(capinfos_result.split(' ')[5])

    else:  # solution for other systems
        os.system("capinfos %s | grep 'Capture duration' | cut -d\" \" -f6 > %s" % (_path, output_capinfos))
    tab = common_lines2table(output_capinfos, "\n")
    try:
        capture_duration_in_minutes = round(float(tab[0][0].replace(',', '.')) / 60.0)
    except:
        capture_duration_in_minutes = 0
    return capture_duration_in_minutes


# Capture time
# °°°°°°°°°°°°
# 3 : get first & last paket time of the dump file
def analyse_capinfos_packet_time(_path):
    # variables
    # ---------
    output_capinfos = "Output_Files/Analyse/output_capinfos1"
    if sys.platform == 'win32':  # solution for Windows
        os.system('capinfos %s | find "packet time" > %s' % (_path, output_capinfos))
    else:  # solution for other systems
        os.system("capinfos %s | grep 'packet time' > %s" % (_path, output_capinfos))
    tab = common_lines2table(output_capinfos, "\n")

    tab1 = tab[0][0].split(":", 1)
    tab2 = tab[1][0].split(":", 1)
    ans = []
    ans.extend(tab1)
    ans.extend(tab2)
    return ans


# functions for ghg and kwh calculations
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# 11 : get the cif value of a particular country/continent/default
def analyse_getCifByCC(data, countryCode):
    cif = data[0]['carbonIntensity']  # defaults
    for i in data:
        if i['countryCode'] == countryCode:
            cif = i['carbonIntensity']
    return cif


def analyse_getCifByCC1(data, countryCode):  # server.py
    cif = data['default']
    # print(cif)
    if countryCode in data.keys():
        cif = data[countryCode]
    return cif


def analyse_calcCifPerTraffic(data, table):
    total = 0.0
    for i in table:
        total += analyse_getCifByCC(data, i['countryCode']) * i['fraction']
    cifAvgPerTraffic = total
    return cifAvgPerTraffic


# 8 : for each communication, get the cif average for that particular traffic
def analyse_calcCifPerTraffic1(data, table):  # server.py
    total = 0.0
    for i in table:
        total += analyse_getCifByCC1(data, i['countryCode']) * i['fraction']
    cifAvgPerTraffic = total
    return cifAvgPerTraffic


# functions convert smartphones and cars
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# 14 : calculate charged smartphones equivalent to CO2 emissions value
def analyse_calcGhg2Smartphone(smartphone_Gco2ePerChargedPhone, sumGhg):
    cvtChargedPhone = round(sumGhg / smartphone_Gco2ePerChargedPhone)
    return cvtChargedPhone


# 15 : calculate distance traveled by car equivalent to CO2 emissions value
def analyse_calcGhg2Car(car_Gco2ePerKm, sumGhg):
    cvtCarKm = sumGhg / car_Gco2ePerKm
    return cvtCarKm


# Electricity Consumption in KWh
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# 9 : calculate the partial sum of both CO2 emissions and energy consumed values
def analyse_partialSumGhgAndKWh(data_size, dataCenterKWhPerByte, telecomKWhPerByte, cifAvgPerTraffic):
    # --------------------------kWh-------------------------------------------------------
    totalDataCenterKWh = data_size * dataCenterKWhPerByte
    totalTelecomKWh = data_size * telecomKWhPerByte
    partial_sumKWh = totalDataCenterKWh + totalTelecomKWh
    # ------------------------gCO2eq------------------------------------------------------
    totalDataCenterGhg = totalDataCenterKWh * cifAvgPerTraffic
    totalTelecomGhg = totalTelecomKWh * cifAvgPerTraffic
    partial_sumGhg = totalDataCenterGhg + totalTelecomGhg
    return [partial_sumKWh, partial_sumGhg]


# 12 : calculate total energy consumed
def analyse_totalKWh(allPartial_sumKWh, capture_duration_in_minutes, deviceKWhPerMin):
    sumKWh = allPartial_sumKWh + (capture_duration_in_minutes * deviceKWhPerMin)
    return sumKWh


# 13 : calculate total CO2 emissions
def analyse_totalGco2eq(allPartial_sumGhg, capture_duration_in_minutes, deviceKWhPerMin, cifCC):
    totalDeviceKWh = capture_duration_in_minutes * deviceKWhPerMin
    sumGhg = allPartial_sumGhg + (totalDeviceKWh * cifCC)
    return sumGhg


# 16 : calculate total CO2 emissions & total energy consumed
def analyse_carbonalyser_calcKwh_calcGhg(data_size, duration, dataCenterKWhPerByte, telecomKWhPerByte, deviceKWhPerMin,
                                         cifCountry, cifDefault):
    totalDataCenterKWh = data_size * dataCenterKWhPerByte
    totalTelecomKWh = data_size * telecomKWhPerByte
    totalDeviceKWh = duration * deviceKWhPerMin
    sumKwh = totalDataCenterKWh + totalTelecomKWh + totalDeviceKWh
    totalDataCenterGhg = totalDataCenterKWh * cifDefault
    totalTelecomGhg = totalTelecomKWh * cifDefault
    totalDeviceGhg = totalDeviceKWh * cifCountry
    sumGhg = totalDataCenterGhg + totalTelecomGhg + totalDeviceGhg
    return [sumKwh, sumGhg]

