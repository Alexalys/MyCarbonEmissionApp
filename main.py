#!/usr/bin/python3

import urllib.request
import os.path
import argparse
import logging
from sendfile import *
from multiprocessing import Process

sys.path.insert(1, "./Modules")
from Modules.traceroute import *
from Modules.inputInfo import *
from Modules.capture import *
from Modules.analyse import *
import scapy.all as scapy
import sys


# logging events
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
stream_h = logging.StreamHandler()
file_h = logging.FileHandler("logs.log")

# set levels and format
stream_h.setLevel(logging.CRITICAL)
file_h.setLevel(logging.DEBUG)
formatter_f = logging.Formatter("%(asctime)s : %(name)s : %(levelname)s : %(message)s")
formatter_s = logging.Formatter("%(message)s")
stream_h.setFormatter(formatter_s)
file_h.setFormatter(formatter_f)
logger.addHandler(stream_h)
logger.addHandler(file_h)


# variables
parsser = argparse.ArgumentParser()
parsser.parse_args()
configur = ConfigParser()
configur.read("ClientConf.ini")
UserInfoFolder = configur.get("Paths", "UserInfoFolder").replace('"', "")
UserInfoFile = UserInfoFolder + "information.txt"

# the capture file can be stored somewhere else (source)
CaptureFolder = configur.get("Paths", "CaptureFolder").replace('"', "")
AnalyseFolder = configur.get("Paths", "AnalyseFolder").replace('"', "")
DatabaseFolder = configur.get("Paths", "DatabaseFolder").replace('"', "")

# the results can be saved somewhere else (destination)
ResultFolder = configur.get("Paths", "ResultFolder").replace('"', "")
StorageFolder = configur.get("Paths", "StorageFolder").replace('"', "")
FolderF = configur.get("Paths", "FolderF").replace('"', "")
TRFolder = configur.get("Paths", "TRFolder").replace('"', "")

Folders = (
    UserInfoFolder,
    CaptureFolder,
    AnalyseFolder,
    DatabaseFolder,
    ResultFolder,
    StorageFolder,
    FolderF,
    TRFolder,
)
# If folder does not exit
for e in Folders:
    if not os.path.exists(e):
        os.makedirs(e)

# argument
# taking arguments into account
# arg0 : main.py
# arg1 : source (directory for dump files)
# arg2 : destination (directory for results)
# variable d'environnement
# print("arguments : ", sys.argv, len(sys.argv))
listOfArguments = sys.argv
arguments = len(sys.argv)
if arguments > 1:
    try:
        if arguments == 2:
            if (
                listOfArguments[1] != "none"
                and os.path.exists(listOfArguments[1]) == True
            ):
                CaptureFolder = listOfArguments[1]
                if CaptureFolder[-1] != "/":
                    CaptureFolder = CaptureFolder + "/"
                print("CaptureFolder : ", CaptureFolder)
        if arguments == 3:
            if (
                listOfArguments[1] != "none"
                and os.path.exists(listOfArguments[1]) == True
            ):
                CaptureFolder = listOfArguments[1]
                if CaptureFolder[-1] != "/":
                    CaptureFolder = CaptureFolder + "/"
                print("CaptureFolder : ", CaptureFolder)
            if listOfArguments != "none" and os.path.exists(listOfArguments[2]) == True:
                ResultFolder = listOfArguments[2]
                if ResultFolder[-1] != "/":
                    ResultFolder = ResultFolder + "/"
                print("ResultFolder : ", ResultFolder)
    except Exception as e:
        logger.error(e)


# Functions
# ---------
def display_welcome():
    login()
    message = (
        "\n"
        + "     MyCarbonEmissionApp  Version 4.0     ".center(80, "*")
        + "\n"
        + "\n"
    )
    datetimeOfAnnalysis = "Current date & time:\t" + str(datetime.datetime.now()) + "\n"
    print("%s%s" % (message, datetimeOfAnnalysis))


def inputInfo(UserInfoFile):
    var_inputInfo = get_info(UserInfoFile)
    time.sleep(1)
    return var_inputInfo


def analyse(
    CaptureFolder, AnalyseFolder, myIP, countryCode, action, listOfFiles, username
):
    print("\n" + " 2 : Start Analysis".center(50, "*") + "\n")
    # current datetime
    filename = str(datetime.datetime.now())
    # get the list of documents to analyse
    if not listOfFiles:
        listOfFiles = analyse_getListOfFiles2Analyse(
            CaptureFolder, action
        )  # (analyse.py @0)
    if listOfFiles:
        # print(listOfFiles)
        # create a dossier where traceroute and geolocalization files per IP address would be saved
        IPgeolocFolder = DatabaseFolder + myIP + "/"
        if not os.path.exists(IPgeolocFolder):
            os.makedirs(IPgeolocFolder)

        # variables
        # ---------
        storage_1 = []
        storage_2 = {}
        dataCenterKWhPerByte = 0.000000000072
        telecomKWhPerByte = 0.000000000152
        deviceKWhPerMin = 0.0001065449011
        deviceKWhPerMin_carbonalyser = 0.00021
        car_Gco2ePerKm = 220
        smartphone_Gco2ePerChargedPhone = 8.3
        # laptopKWhPerMin = 0.0001065449011
        # smartphoneKWhPerMin = 0.00001141552511
        # deviceKWhPerMin = 0.00021
        for f in listOfFiles:
            print(f.center(70, "*"))
            storage_2[f] = {}
            # register date and time of analysis
            storage_2[f]["datetime"] = str(datetime.datetime.now())
            # tranform capture to output file (extract the important part) (analyse.py @1)
            #print('Capture folder',CaptureFolder + f, 'Analyse folder',AnalyseFolder)
            file3 = analyse_capture2Output1(CaptureFolder + f, AnalyseFolder)
            # transform output file to table format (analyse.py @2)
            storage_1 = analyse_lines2table(file3, "=")
            #print('Storage',storage_1)
            capture_time = analyse_capinfos_packet_time(
                CaptureFolder + f
            )  # (analyse.py @3)
            storage_2[f][capture_time[0]] = capture_time[1].lstrip(" ")
            storage_2[f][capture_time[2]] = capture_time[3].lstrip(" ")
            # other useful info
            storage_2[f]["username"] = username
            storage_2[f]["userIP"] = myIP
            storage_2[f]["userCC"] = countryCode
            # total number of packets
            storage_2[f]["numberOfPackets"] = len(storage_1)
            # total size of packets (analyse.py @4)
            storage_2[f]["numberOfBytes"] = analyse_totalFrameLength(storage_1)
            # number of paquets that came in
            incomingPacketFrameLen = []
            for i in range(len(storage_1)):
                if storage_1[i][4] == myIP:
                    incomingPacketFrameLen.append(storage_1[i][0])
            storage_2[f]["numberOfPacketsIn"] = len(incomingPacketFrameLen)
            storage_2[f]["numberOfBytesIn"] = analyse_totalFrameLength1(
                incomingPacketFrameLen
            )  # (analyse.py @5)
            # number of paquets that came out
            outgoingPacketFrameLen = []
            for i in range(len(storage_1)):
                if storage_1[i][5] == myIP:
                    outgoingPacketFrameLen.append(storage_1[i][0])
            storage_2[f]["numberOfPacketsOut"] = len(outgoingPacketFrameLen)
            storage_2[f]["numberOfBytesOut"] = analyse_totalFrameLength1(
                outgoingPacketFrameLen
            )  # (analyse.py @5)
            # sort dns queries
            storage_3 = analyse_getDnsQueries(storage_1, myIP)  ##(analyse.py @6)
            # print(storage_3)
            print("Analysing ...")
            # traceroute
            allPartial_sumKWh = 0.0
            allPartial_sumGhg = 0.0
            tableOfCif = analyse_getGhgPerKwhFromDatabase1()  # (analyse.py @7)
            partialTotal = 0.0
            for i in storage_3:
                if i["framelength"] != 0:
                    tableOfFractionsAndCif = i[
                        "fraction"
                    ] = traceroute_fromHops2Fraction(
                        i["QueryName"], i["IPAddress"], countryCode, IPgeolocFolder
                    )
                    cifAvgPerTraffic = i["ghgPerTraffic"] = analyse_calcCifPerTraffic(
                        tableOfCif, tableOfFractionsAndCif
                    )  # (analyse.py @8)
                    storage_4 = analyse_partialSumGhgAndKWh(
                        i["framelength"],
                        dataCenterKWhPerByte,
                        telecomKWhPerByte,
                        cifAvgPerTraffic,
                    )  # (analyse.py @9)
                    allPartial_sumKWh += storage_4[0]
                    allPartial_sumGhg += storage_4[1]
                    partialTotal += i["framelength"]
            capture_duration_in_minutes = analyse_capinfos_minutes(
                CaptureFolder + f
            )  # (analyse.py @10)
            storage_2[f]["capture duration (min)"] = capture_duration_in_minutes
            # other applications
            remainder = storage_2[f]["numberOfBytes"] - partialTotal
            cifDefault = analyse_getCifByCC(tableOfCif, "defaults")  # (analyse.py @11)
            cifCC = analyse_getCifByCC(tableOfCif, countryCode)
            if remainder > 0:
                storage_5 = analyse_partialSumGhgAndKWh(
                    remainder, dataCenterKWhPerByte, telecomKWhPerByte, cifDefault
                )  # change default to cc   #(analyse.py @9)
                remainder_sumKWh = storage_5[0]
                remainder_sumGhg = storage_5[1]
                # print('remainder : ', remainder)
            else:
                remainder_sumKWh = 0.0
                remainder_sumGhg = 0.0
            storage_2[f]["sumKWh"] = analyse_totalKWh(
                allPartial_sumKWh + remainder_sumKWh,
                capture_duration_in_minutes,
                deviceKWhPerMin,
            )  # (analyse.py @12)
            storage_2[f]["sumGhg (gCO2eq)"] = analyse_totalGco2eq(
                allPartial_sumGhg + remainder_sumGhg,
                capture_duration_in_minutes,
                deviceKWhPerMin,
                cifCC,
            )  # (analyse.py @13)
            # conversion from GHG to Km and charged smarthphones
            storage_2[f]["gCo2ePerChargedSmartphone"] = analyse_calcGhg2Smartphone(
                smartphone_Gco2ePerChargedPhone, storage_2[f]["sumGhg (gCO2eq)"]
            )  # (analyse.py @14)
            storage_2[f]["gCo2ePerChargedKm"] = analyse_calcGhg2Car(
                car_Gco2ePerKm, storage_2[f]["sumGhg (gCO2eq)"]
            )  # (analyse.py @15)

            # carbonalyser format but with new values
            storage_2[f]["carbonalyser format"] = {}
            storage_2[f]["carbonalyser format"][
                "description"
            ] = "carbonalyser format but with new values"
            tab = analyse_carbonalyser_calcKwh_calcGhg(
                storage_2[f]["numberOfBytes"],
                capture_duration_in_minutes,
                dataCenterKWhPerByte,
                telecomKWhPerByte,
                deviceKWhPerMin,
                cifCC,
                cifDefault,
            )  # (analyse.py @16)
            storage_2[f]["carbonalyser format"]["sumKwh"] = tab[0]
            storage_2[f]["carbonalyser format"]["sumGhg (gCO2eq)"] = tab[1]
            storage_2[f]["carbonalyser format"][
                "gCo2eqPerChargedSmartphone"
            ] = analyse_calcGhg2Smartphone(
                smartphone_Gco2ePerChargedPhone, tab[1]
            )  # (analyse.py @14)
            storage_2[f]["carbonalyser format"][
                "gCo2eqPerChargedKm"
            ] = analyse_calcGhg2Car(
                car_Gco2ePerKm, tab[1]
            )  # (analyse.py @15)

            # carbonalyser format with catbonalyser values
            storage_2[f]["carbonalyser values"] = {}
            storage_2[f]["carbonalyser values"][
                "description"
            ] = "carbonalyser format with catbonalyser values (region fixed as France)"
            tab = analyse_carbonalyser_calcKwh_calcGhg(
                storage_2[f]["numberOfBytes"],
                capture_duration_in_minutes,
                dataCenterKWhPerByte,
                telecomKWhPerByte,
                deviceKWhPerMin_carbonalyser,
                34.8,
                512,
            )  # (analyse.py @16)
            storage_2[f]["carbonalyser values"]["sumKwh"] = tab[0]
            storage_2[f]["carbonalyser values"]["sumGhg (gCO2eq)"] = tab[1]
            storage_2[f]["carbonalyser values"][
                "gCo2eqPerChargedSmartphone"
            ] = analyse_calcGhg2Smartphone(
                smartphone_Gco2ePerChargedPhone, tab[1]
            )  # (analyse.py @14)
            storage_2[f]["carbonalyser values"][
                "gCo2eqPerChargedKm"
            ] = analyse_calcGhg2Car(
                car_Gco2ePerKm, tab[1]
            )  # (analyse.py @15)

            # Top 10
            print("Top 10 (sub)domain".center(50, "*"))
            storage_3 = sorted(storage_3, key=lambda i: i["framelength"], reverse=True)
            size = len(storage_3)
            storage_6 = []
            # if size < 30:
            storage_6 = analyse_top10(
                0, size, storage_2[f]["numberOfBytes"], storage_3
            )  # (analyse.py @17)
            # else:
            # 	storage_6 = analyse_top10(0, 30, storage_2[f]['numberOfBytes'], storage_3)
            storage_2[f]["top10"] = storage_6
            try:
                ipv4_ipv6 = analyse_ipType(storage_1, myIP)  # (analyse.py @18)
            except:
                continue
            storage_2[f]["ipv4 & ipv6 addresses"] = ipv4_ipv6
            # save dns query dico
            storage_2[f]["QueryInfo"] = storage_3

        for k in listOfFiles:
            # Remove Capture File or save to storage
            # os.remove(CaptureFolder+f)
            new_filename = storage_2[k]["datetime"]
            new_filename = new_filename.replace(":", "_")
            new_filename = new_filename.replace(" ", "_")
            new_filename = new_filename.replace("-", "_")
            new_filename = new_filename.replace(".", "_")
            try:
                os.rename(CaptureFolder + k, CaptureFolder + new_filename + ".pcapng")
                '''
                Despite of the commands to system it was decided to use the builtin methods
                '''

                import gzip
                import shutil
                with open((CaptureFolder + new_filename + ".pcapng"), 'rb') as f_in:
                    with gzip.open((CaptureFolder + new_filename + ".pcapng"+'.gz'), 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                shutil.move(CaptureFolder + new_filename + ".pcapng.gz", StorageFolder + new_filename + ".pcapng.gz")

                # os.system("gzip %s" % (CaptureFolder + new_filename + ".pcapng"))
                # os.system(
                #     "mv "
                #     + CaptureFolder
                #     + new_filename
                #     + ".pcapng.gz"
                #     + " "
                #     + StorageFolder
                #     + new_filename
                #     + ".pcapng.gz"
                # )
            except FileNotFoundError:  # possible solution to the FileNotFoundError exception
                if os.path.exists(CaptureFolder + k):
                    os.rename(
                        CaptureFolder + k, CaptureFolder + new_filename + ".pcapng"
                    )
                    #os.system("gzip %s" % (CaptureFolder + new_filename + ".pcapng"))
                    '''
                    Despite of the commands to system it was decided to use the builtin methods
                    '''
                    import gzip
                    import shutil
                    with open((CaptureFolder + new_filename + ".pcapng"), 'rb') as f_in:
                        with gzip.open((CaptureFolder + new_filename + ".pcapng" + '.gz'), 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    shutil.move(CaptureFolder+new_filename+".pcapng.gz",StorageFolder+new_filename+".pcapng.gz")

                    # os.system(
                    #     "mv "
                    #     + CaptureFolder
                    #     + k
                    #     + " "
                    #     + StorageFolder
                    #     + new_filename
                    #     + ".pcapng.gz"
                    # )
            # listOfFiles.remove(k)
        # print(json.dumps(storage_2, indent=4))
        # Save Analysis to file : the file is to be sent to the server
        result_file_path = saveAnalysis(
            ResultFolder, storage_2, username + "_" + filename
        )
        folder_file = result_file_path.split("/", -1)
        # send file to ftp server
        print("Send file to server", folder_file)
        try:
            loginfo = common_readFromConfFile("ClientConf.ini")
            connectServer(
                loginfo[0], loginfo[1], folder_file[0] + "/" + folder_file[1], True
            )
        except Exception as e:
            logger.error(e)

    else:
        print("No dump files in Capture_Files directory !")
        time.sleep(3)


def removeOutputFiles(folder):
    for i in os.listdir(folder):
        if os.path.exists(folder + i):
            os.remove(folder + i)


def detect_changed_interface(captureInt):
    '''
    if sys.platform == "linux" or sys.platform == "linux2":
        # print('linux')
        interface = os.popen(
            "ip route get 8.8.8.8 | cut -d ' ' -f 5 -s|head -n 1 ", "r"
        ).read()
    elif sys.platform == "darwin":
        # print('MAC OS X')
        interface = os.popen(
            "route get 8.8.8.8 | grep interface | cut -f2 -d':' ", "r"
        ).read()
    interface = str(interface).rstrip()
    '''
    interface = get_interface_name()
    if captureInt != interface:
        with open(UserInfoFile, "r") as jsonFile:
            data = json.load(jsonFile)
        data["information"][0]["interface Name"] = interface
        with open(UserInfoFile, "w") as jsonFile:
            json.dump(data, jsonFile)

        return True
    return False


def saveAnalysis(folder, data, filename):
    filename = filename.replace(":", "_")
    filename = filename.replace(" ", "_")
    filename = filename.replace("-", "_")
    filename = filename.replace(".", "_")
    common_writeToJsonFile(folder + filename + ".json", data)
    return folder + filename + ".json"


def lsof():
    n = 0
    while n != 100:
        n += 1
        # Using readlines()
        os.system(
            'lsof -i -n -P | grep -E "(LISTEN|ESTABLISHED|UDP)" >> Output_Files/Analyse/applications.txt '
        )
        time.sleep(1)


def lsof_once():
    os.system(
        'lsof -i -n -P | grep -E "(LISTEN|ESTABLISHED|UDP)" >> Output_Files/Analyse/applications.txt '
    )


def netstat():
    n = 0
    while n != 100:
        n += 1
        # Using readlines()
        os.system("netstat -nab >> ./Output_Files/Analyse/applications.txt")
        time.sleep(1)


def netstat_once():
    os.system("netstat -nab >> ./Output_Files/Analyse/applications.txt")


def netstat_every_ten():
    n = 0
    # For tests changed from 350 to 20
    while n != 350:
        n += 1
        os.system("netstat -nab >> ./Output_Files/Analyse/applications.txt")
        time.sleep(9)


def check_for_connections_once():
    if sys.platform == 'win32':
        netstat_once()
    else:
        lsof_once()


def check_for_connections():
    if sys.platform == 'win32':
        netstat()
    else:
        lsof()


def lsof_every_ten():
    n = 0
    # For tests changed from 350 to 20
    while n != 350:
        n += 1
        os.system(
            'lsof -i -n -P | grep -E "(LISTEN|ESTABLISHED|UDP)" >> Output_Files/Analyse/applications.txt '
        )
        time.sleep(9)


def check(folder):
    file = os.listdir(folder)
    name = ""
    for i in file:
        if i[:20] == "conso_macbook_tshark":
            name = i
    print("Name from check", name)
    n = 0
    while n != 100:
        n += 1

        packets = scapy.rdpcap(folder + name)
        SYN = 0x02
        for packet in packets:
            if packet.haslayer("TCP"):
                F = packet["TCP"].flags
                if F & SYN:
                    print("NEW SYN")
        time.sleep(1)
    print("END CHECK")


def process_packet(pkt):
    if sys.platform == 'win32':
        netstat_once()
    else:
        lsof_once()
    logger.info("SYN found. Initiating lsof")


def check_syn():

    sniffer = scapy.AsyncSniffer(
        prn=process_packet, filter="tcp[tcpflags] == tcp-syn", store=False
    )
    sniffer.start()
    logger.info("Sniff started")
    return sniffer


def main():
    logger.info("program started ")
    display_welcome()
    json_inputInfo = inputInfo(UserInfoFile)
    logger.info("user logged in ")
    while True:
        try:
            # start capturing
            captureInt = json_inputInfo["information"][0]["interface Name"]
            logger.info("capture started ")
            p1 = Process(target=autoCapture, args=(CaptureFolder, captureInt))
            p1.start()

            p2 = Process(target=check_for_connections)
            p2.start()
            p2.join()

            sniffer = check_syn()
            if sys.platform == 'win32':
                p3 = Process(target=netstat_every_ten)
            else:
                p3 = Process(target=lsof_every_ten)
            p3.start()
            p1.join()
            p3.join()
            sniffer.stop()
            logger.info("Sniff ended")
            logger.info(p1.is_alive)
            logger.info("Capture terminated")
            changedInt = detect_changed_interface(captureInt)
            # analysing the resulted capture
            logger.info("Analysing the capture")
            analyse(
                CaptureFolder,
                AnalyseFolder,
                json_inputInfo["information"][0]["ip address"],
                json_inputInfo["information"][0]["CountryCode"],
                "a",
                [],
                json_inputInfo["information"][0]["username"],
            )
            removeOutputFiles(AnalyseFolder)
            logger.info("Ending analyse")
            if changedInt:
                json_inputInfo = inputInfo(UserInfoFile)
                logger.info("Interface changed ")
            logger.info("Changes of interface checked")
        except Exception as e:
            logger.critical(e)
            if e == urllib.error.URLError:
                time.sleep(3)
                continue
            sys.exit("\n" + " Abnormal program termination ".center(70, "-") + "\n")

            #continue


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        removeOutputFiles(AnalyseFolder)
        logger.info("Program stopped")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
