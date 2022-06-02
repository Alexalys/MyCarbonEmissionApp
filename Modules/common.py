#!/usr/bin/python3
import json
import os
from configparser import ConfigParser


# functions
# ---------

# Create a table from lines
def common_lines2table(file, separator):
    storage = []
    with open(file, 'r') as fic:
        lines = fic.readlines()

    for line in lines:
        tableOfFields = line.split(separator)
        storage.append(tableOfFields)
    return storage


def common_readFromJsonFile(_path):
    with open(_path, 'r') as jsonFile:
        data = json.load(jsonFile)
        jsonFile.close()
        return data


def common_writeToJsonFile(_path, data):
    try:
        with open(_path, 'w') as jsonFile:
            json.dump(data, jsonFile)
            jsonFile.close()
    except OSError:
        new_path = _path.replace(':', '_')
        with open(new_path, 'w') as jsonFile:
            json.dump(data, jsonFile)
            jsonFile.close()


def common_appendToJsonFile(_path, data):
    with open(_path, 'a') as jsonFile:
        json.dump(data, jsonFile)
        jsonFile.close()


def common_writeToFile(dico,_file):
	# parameter : dico => a dictionnary consisting a public IP address and the number of hops it takes to reach it
    # _file = "Output_Files/Traceroute/dicoTraceroute.csv"
    dicoKeys = ["IPAddress", ""]
    test = os.path.exists(_file)
    with open(_file, mode="a", newline="") as csvFile:
        writer = csv.DictWriter(csvFile, fieldnames=dicoKeys)
        if test == False:
            writer.writeheader()
        writer.writerow(dico)
        csvFile.close()


def common_readFromFile(_file):
    # _file = "Output_Files/Traceroute/dicoTraceroute.csv"
    table = []
    if os.path.exists(_file) == True:
        with open(_file, mode="r", newline="") as csvFile:
            reader = csv.DictReader(csvFile)
            for row in reader:
                table.append({"IPAddress": row['IPAddress'], "Hop": row['Hop']})
            csvFile.close()
    return table


def common_readFromConfFile(_file):
    parser = ConfigParser()
    parser.read(_file)
    myname = parser.get('User', 'name')
    mypassword = parser.get('User', 'password')
    return([myname,mypassword])