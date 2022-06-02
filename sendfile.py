import pysftp
import os
import sys
import time
import getpass
from configparser import ConfigParser
sys.path.insert(1, './Modules')
from Modules.common import *

 
def connectServer(username, password, fileTOsend=None, send=False):
    cnopts = pysftp.CnOpts()
    cnopts.hostkeys = None 
    try:
        with pysftp.Connection(host="134.59.130.200", username=username, password=password, port=80, cnopts=cnopts) as sftp:
             if send :
                 with sftp.cd('/mnt'):
                    with sftp.cd('Results_Server'):
                        sftp.put(fileTOsend)
                        print('Done.')
             else: print('Connection successfully established ')
             return(True)
    except Exception as e:
        print(e)
        return(False)


# Login
def login():
    print("Login ....\t")
    time.sleep(1)
    try:
        loginfo = common_readFromConfFile('ClientConf.ini')
        time.sleep(1)
        verified = connectServer(loginfo[0], loginfo[1])
    except:
        myname = input("Enter your name:")
        print(myname)
        mypassword = getpass.getpass(prompt="Enter your password:")
        print(mypassword)
        verified = connectServer(myname, mypassword)
        if verified:
            parser0 = ConfigParser()
            parser0.read('ClientConf.ini')
            file = open("ClientConf.ini", 'r+')
            parser0.set('User', 'name', myname)
            parser0.set('User', 'password', mypassword)
            parser0.write(file)
            file.close()
            time.sleep(1)
    if not verified: sys.exit("Try again")

