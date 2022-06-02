#!/usr/bin/python3
import os
import os.path
import datetime
import sys


def autoCapture(CaptureFolder, interface):
    print("\n" + "   1 : Start Auto Capture   ".center(60, '*') + "\n")
    # capturefile naming 
    saveFileAs = "conso_macbook_tshark.pcapng"
    if os.path.exists(CaptureFolder):
        newfilename = str(datetime.datetime.now())
        newfilename = newfilename.replace(':', '')
        newfilename = newfilename.replace(' ', '')
        newfilename = newfilename.replace('-', '')
        newfilename = newfilename.replace('.', '')
        saveFileAs = saveFileAs + "_" + newfilename + ".pcapng"
    if sys.platform != 'win32':
        try:
            os.popen('killall -9 tshark &> /dev/null').read()
        except OSError as ex:
            print('Exception %s has occured' % type(ex).__name__)
    # else:
    #     try:
    #         os.popen('taskkill /im tshark')
    #     except OSError as ex:
    #         print('Exception %s has occured' % type(ex).__name__)

    print('Interface name',interface)
    # start capture
    # For tests changed from 3600 to 60
    try:
        print("\n Capturing... \n ")
        os.system('tshark -Q -i %s -a duration:3600 -s 96 -n -w %s ' % (interface, CaptureFolder + saveFileAs))
    except KeyboardInterrupt:
        pass

    if sys.platform == 'win32':
        os.system('ping -n XXX 127.0.0.1 >nul')
    else:
        os.system('sleep 2')

