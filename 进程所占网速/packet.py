'''
Author: your name
Date: 2020-09-22 14:31:28
LastEditTime: 2020-09-25 17:09:55
LastEditors: Please set LastEditors
Description: In User Settings Edit
FilePath: /opt/sniffcatch/packet.py
'''

import os
import time
import _thread
from ctypes import *
from ctypes import cdll

class timeval(Structure):
    _fields_=[('tv_sec', c_long),
             ('tv_usec', c_long)]

class pcap_pkthdr(Structure):
    _fields_=[('ts', timeval),
              ('caplen', c_uint),
              ('len', c_uint)]

class Result(Structure):
    _fields_=[('a', c_uint),
             ('b', c_uint)]


def ports():
    tmpdict = {}
    process = {}
    with open("/proc/net/tcp", "r") as ff:
        for eachline in ff :
            eachline = eachline.strip()
            if eachline.startswith("sl"):
                continue
            if eachline:
                tmpdata = eachline.split()
                tmpport = int(tmpdata[1].split(":")[-1], 16)
                tmpsocket = tmpdata[9]
                tmpdict[tmpsocket] = tmpport
    with open("/proc/net/tcp6", "r") as ff:
        for eachline in ff :
            eachline = eachline.strip()
            if eachline.startswith("sl"):
                continue
            if eachline:
                tmpdata = eachline.split()
                tmpport = int(tmpdata[1].split(":")[-1], 16)
                tmpsocket = tmpdata[9]
                tmpdict[tmpsocket] = tmpport
    for pid in os.listdir("/proc/"):
        try:
            int(pid)
            for fd in os.listdir("/proc/%s/fd/" % pid):
                try:
                    content = os.readlink('/proc/%s/fd/%s' % (pid, fd)).split("[")[-1].split("]")[0]
                    with open("/proc/%s/cmdline" % pid, "r") as ff1:
                        data = ff1.readline()
                        process[tmpdict[content]] = data
                except:
                    continue
        except:
            continue
    return process


def handle(a):
    cur = cdll.LoadLibrary('/opt/sniffcatch/packet.so')
    functype = CFUNCTYPE(c_void_p, c_char_p, c_ushort, c_uint)  # c_char_p
    c_callback_python = functype(getPacket)
    cur.handle1(c_callback_python)


def getPacket(result, port, length):
    try:
        direct = result.decode()
        global speed
        if not port in speed[direct]:
            speed[direct][port] = length
        else:
            speed[direct][port] += length
    except:
        pass


def main():
    try:
        _thread.start_new_thread(handle, ("Thread-1", ) )
    except:
        print ("Error: 无法启动线程")
    global speed
    while 1:
        speed = {"rx": {}, "tx": {}}
        time.sleep(1)
        process = ports()
        # print(process)
        # print(speed)
        #  处理tx
        os.system('clear')
        print('tx')
        print('port\tspeed\tcmd')
        for eachport, eachlength in speed["tx"].items():
            try:
                cmd = process[eachport][:30]
            except:
                continue
            unit = ["B/s", "KB/s", "MB/s"]
            level = 0
            while 1:
                if eachlength / 1024 <1:
                    break
                else:
                    eachlength = round(eachlength / 1024, 2)
                    level += 1

            print('\r%s\t%s %s\t%s' % (eachport, eachlength, unit[level], cmd))

        print('\n\n')
        #  处理rx
        print('rx')
        print('port\tspeed\t\tcmd')
        for eachport, eachlength in speed["rx"].items():
            try:
                cmd = process[eachport][:50]
            except:
                continue
            unit = ["B/s", "KB/s", "MB/s"]
            level = 0
            while 1:
                if eachlength / 1024 <1:
                    break
                else:
                    eachlength = round(eachlength / 1024, 2)
                    level += 1

            print('\r%s\t%s %s\t\t%s' % (eachport, eachlength, unit[level], cmd))
if __name__ == "__main__":
    main()

