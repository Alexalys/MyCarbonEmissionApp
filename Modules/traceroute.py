#!/usr/bin/python3
import os.path
import time
import urllib
import urllib.request

from common import *


# functions
# ---------

def traceroute_writeToDatabaseFile(data, _folder, userIP):
    _file = './' + _folder + userIP + ".json"
    common_writeToJsonFile(_file, data)


def traceroute_readFromDatabaseFile(_folder, userIP):
    _file = _folder + userIP + ".json"
    data = common_readFromJsonFile(_file)
    return data


def traceroute_geoIp(ipAddr):
    jsonObject = json.dumps({})
    if ipAddr == "" :return jsonObject
    try:
        f = urllib.request.urlopen('http://ip-api.com/json/' + ipAddr)
    except urllib.error.HTTPError:
        time.sleep(22)
        return traceroute_geoIp(ipAddr)
    if f.getcode() == 200:
        ans = f.read().decode('utf-8')
        jsonAns = json.loads(ans)
        if "country" in jsonAns:
            # jsonObject = {"country":jsonAns["country"], "isp": jsonAns["isp"], "countryCode" : jsonAns["countryCode"]}
            jsonObject = jsonAns["countryCode"]
        else:
            # jsonObject = {"country": "Unknown", "isp": "Unknown",  "countryCode" : "Unknown"}
            jsonObject = "FR"
    return jsonObject


def traceroute_getHops(theIP, ipType):  # parameter : tableIpHop = table of IPs and number of hops
    filenameTraceroute = "Output_Files/Traceroute/output_traceroute"
    # if ipType == 'ipv4':
    #     output = os.popen('traceroute -n -n -q 1 -w 1 -m 15 ' + theIP + '>' + filenameTraceroute + '& > /dev/null' ).read()
    # if ipType == 'ipv6':
    #     output = os.popen('traceroute6 -n -n -q 1 -w 1 -m 15 ' + theIP + '>' + filenameTraceroute + '& > /dev/null' ).read()
    table = common_lines2table(filenameTraceroute, ' ')
    t = len(table)
    y = 0
    if t > 9:
        for i in range(9):
            table[i].pop(0)
    if t <= 9:
        for i in range(t):
            table[i].pop(0)
    # traceroute_writeToFile({"IPAddress":theIP, "Hop":hop, "allIP":tab)
    return table


def traceroute_findCdnInDnsQueryName(dnsQryName):
    listOfCdn = ['akamai', 'edgekey', 'akamaiedge', 'cloudflare', 'cloudfront', 'fastly']
    for i in listOfCdn:
        if i in dnsQryName:
            return True
        else:
            return False


def traceroute_fromHops2Fraction(dnsQryName, ip, countryCode, _folder):  # dict ip addr
    tab = []
    ans = []
    _smallDict = {}
    countryCodesEU = ["BE", "BG", "CZ", "DK", "DE", "EE", "IE", "EL", "ES", "FR", "HR", "IT", "CY", "LV", "LT", "LU",
                      "HU", "MT", "NL", "AT", "PL", "PT", "RO", "SI", "SK", "FI", "SE"]
    if os.path.exists(_folder + ip + ".json"):
        ans = traceroute_readFromDatabaseFile(_folder, ip)
    else:
        if traceroute_findCdnInDnsQueryName(dnsQryName) == True:
            ans = [{"countryCode": countryCode, "fraction": 1.0}]
        else:
            _dict = traceroute_geoIp(ip)
            if _dict == countryCode:
                ans = [{"countryCode": _dict, "fraction": 1.0}]
            elif _dict in countryCodesEU:
                ans = [{"countryCode": "EU", "fraction": 1.0}]
            else:
                if ip.find(':') != -1:
                    try:
                        table = traceroute_getHops(ip, 'ipv6')
                    except Exception as e:
                        ans = [{"countryCode": "default", "fraction": 1.0}]
                else:
                    try:
                        table = traceroute_getHops(ip, 'ipv4')
                    except Exception:
                        pass
                try:
                    t = len(table)
                    # ms = float(table[t-1][len(table[t-1])-2])
                    try:
                        ms = float(table[t - 1][len(table[t - 1]) - 2])
                    except:
                        # ms = 30000.0 #just to trigger the "else" condition
                        try:
                            ms = float(table[t - 2][len(table[t - 1]) - 2])
                        except:
                            ms = 30000.0  # just to trigger the "else" condition
                    if table[t - 1][2] != "*\n" and ms <= 50.0:
                        ans = [{"countryCode": "EU", "fraction": 1.0}]
                    else:
                        y = ""
                        for i in range(t - 2):
                            if table[i][2] != "*\n":
                                y = traceroute_geoIp(table[i][2])
                                tab.append(y)
                            else:
                                tab.append(y)
                        tab.append(_dict)
                        tab.sort()
                        k = tab[len(tab) - 1]
                        for j in tab:
                            if k != j:
                                ans.append({"countryCode": j, "fraction": float(tab.count(j) / float(len(tab)))})
                            k = j
                            time.sleep(2)
                except Exception as e:
                    pass
    if not os.path.exists(_folder + ip + ".json"):
        traceroute_writeToDatabaseFile(ans, _folder, ip)
    return ans
