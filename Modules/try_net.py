# coding: utf-8
import os
import sys


def info_netstat():
    with open('../Output_Files/Analyse/applications.txt', 'r') as f:
        lines = f.readlines()
    filtered_array = []
    #print(lines)
    for line in lines:
        filtered_array.append([elem.rstrip('\n') for elem in line.split(' ') if elem != ''])
    final_array = []
    #print(filtered_array)
    for element_indx in range(0, len(filtered_array)):
        result_array = []
        if ('LISTENING' or 'ESTABLISHED' or 'UDP') in filtered_array[element_indx]:
            try:
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
    print(final_array)
    return final_array

    # for line_index in range(0,len(result)):
    #     result[line_index]
    #     if result[line_index].startswith('['):



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


def windows_interface_name(metrics):
    """
    Get used interface name in Windows depending on the metrics,
    should be called when you know the ip and metrics of an interface
    """
    results = (os.popen('netsh int ipv4 show interfaces').readlines())
    results = [list(filter(None, line.split(' '))) for line in results]
    interface_name = ''
    print(results)
    for line in results:
        try:
            if line[1] == metrics:

                for status in line:
                    if status.endswith('connected'):
                        interface_name = ' '.join(line[line.index(status)+1:len(line)])
                        interface_name = interface_name.replace('\n','')
                #interface_name = line[0]
        except IndexError:
            continue

    return interface_name


import json
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



#sys.setdefaultencoding('utf-8')
#info_netstat()
#print(u''.join())
#common_writeToJsonFile('fe80::6de0:65aa:a051:c0e7.json', {'hey':'Alex'})
os.remove('pp.txt')