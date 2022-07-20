# !/usr/bin/python3
from common import common_readFromJsonFile, common_writeToJsonFile
import sys
import os.path
import time
import urllib
import urllib.request
import re
import json
from configparser import ConfigParser


def get_info(_path):
    global ipAddr
    global intName
    folder = "Output_Files/InputInfo/"
    username = get_username()
    intName = ""
    ipAddr = ""

    try:
        intName = get_interface_name()

    except Exception as e:

        intName = input("Interface [%s] : " % intName)
    try:
        ipAddr = get_ip_addr(intName)

    except Exception as e:

        ipAddr = input("IPv4 Address [%s] : " % ipAddr)
    try:
        countryCode = get_country_code()
    except:
    	  countryCode = input("Country code [FR] : ") or "FR"
    data = {"information": [{'interface Name': intName, 'ip address': ipAddr, 
                            'CountryCode': countryCode, 'username': username}]} 
    common_writeToJsonFile(_path, data)
    
    return data
    

def get_from_json(_path):
    if not os.path.exists(_path):
        get_info(_path)
    data = common_readFromJsonFile(_path)
    return data


def get_interface_name():
    int_name = ""
    if sys.platform == "linux" or sys.platform == "linux2":
        int_name = os.popen("ip route get 8.8.8.8 | cut -d ' ' -f 5 -s|head -n 1 ").read()
    elif sys.platform == "darwin":
        int_name = os.popen("route get 8.8.8.8 | grep interface | cut -f2 -d':' ").read()
    elif sys.platform == "win32":
        int_addr, metrics = windows_interface_ip_metrics()
        #int_name = windows_interface_name(metrics)
        int_name = windows_interface_name_2(int_addr)
    int_name = int_name.replace('\n','')
    return int_name


def get_ip_addr(int_name):
    ip_addr = ""
    if sys.platform == "linux" or sys.platform == "linux2":
        ip_addr = os.popen("ip -f inet -o addr show %s | awk '/inet / {print $4} ' |"
                 "cut -d ""/"" -f1 " % int_name).read()
    elif sys.platform == "darwin":
        ip_addr = os.popen("ifconfig %s | grep 'inet ' | cut -d ' ' -f 2 " % int_name).read()
    elif sys.platform == "win32":
        ip_addr, metrics = windows_interface_ip_metrics()
    ip_addr = ip_addr.replace('\n', '')
    return ip_addr


def get_username():
    parser = ConfigParser()
    parser.read('ClientConf.ini')
    username = parser.get('User', 'name')
    return username


def get_country_code():
    url = 'http://ipinfo.io/json'
    response = urllib.request.urlopen(url)
    localisation_data = json.load(response)
    return localisation_data['country']


def windows_interface_ip_metrics():
    """
    Get interface ip and metrics in Windows
    """
    results = (os.popen('route print 0.0.0.0').readlines())
    result_gateway = ''
    results = [list(filter(None, line.split(' '))) for line in results]
    metrics = ''

    for line in results:
        for name in line:
            if name == '0.0.0.0':
                result_gateway = line[-2]
                metrics = line[-1].replace('\n','')
                break
        if result_gateway:
            break

    return result_gateway, metrics


def windows_interface_name_2(ip):
    result_int = ''
    lines = os.popen('ipconfig').readlines()
    for line in lines:
        if ip in line:
            new_lines = lines[lines.index(line) - 4].split(' ')
            for indx in range(len(new_lines) - 1, 0, -1):
                if new_lines[indx][0].isupper():
                    correct_int = new_lines[indx:len(new_lines)]
                    result_int = ' '.join(correct_int)
                    break

    return result_int[0:-2]


def windows_interface_name(metrics):
    """
    Get used interface name in Windows depending on the metrics,
    should be called when you know the ip and metrics of an interface
    """
    results = (os.popen('netsh int ipv4 show interfaces').readlines())
    results = [list(filter(None, line.split(' '))) for line in results]
    interface_name = ''
    for line in results:
        try:
            if line[1] == metrics:

                for status in line:
                    if status.endswith('connected'):
                        print(interface_name)
                        interface_name = ' '.join(line[line.index(status)+1:-1])
                        interface_name = interface_name.replace('\n','')
                """
                Get ID instead of name
                """
                #interface_name = line[0]
        except IndexError:
            continue

    return interface_name



