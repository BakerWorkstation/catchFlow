'''
Author: your name
Date: 2020-10-13 11:20:33
LastEditTime: 2020-11-09 10:37:04
LastEditors: Please set LastEditors
Description: In User Settings Edit
FilePath: /opt/sniffcatch/6.py
'''

import json
import time
from scapy.all import *
# packets = rdpcap('/root/1.pcap')


# for p in packets:
#     # try:
#     #     # data = p.payload.payload.payload.load
#     #     # print(p.payload.payload.window)
#     # except:
#     #     continue
#     # if data:
#     p.show()
#         # print(type(data))
#         # dlist.append(data)
#         # wrpcap('/root/2.pcap', [data])


'''
@description:    将字符型IP地址转换成整形数值
@param {type}    ip(string)
@return:         value(int)
'''
def convert_ip_to_number(ip_str):
    ret = 0
    ip_str=ip_str.strip()
    parts = ip_str.split('.')
    if len(parts) == 4:
        ret = int(parts[0]) * 256 * 256 * 256 + int(parts[1]) * 256 * 256 + int(parts[2]) * 256  + int(parts[3])
    return ret


def handle(pointer, key_hash, sip, seq, ack, length, options, func):
    if pointer[key_hash]["sip"] == sip:
        # 源地址等于初始源地址，数据方向  源 -> 目的
        direct = "send"
        # 优先处理sack
        if options:
            for i in options:
                if 'SAck' == i[0]:
                    newAck = i[1][-1] - pointer[key_hash]["ack_seq"]
                    newSeq = pointer[key_hash]["drop"].pop(0)
                    pointer[key_hash]["send_packet"] += 1
                    # pointer[key_hash]["send_len"] += length
                    pointer[key_hash]["last_len"] = 0
                    pointer[key_hash]["ack"] = newAck
                    pointer[key_hash]["seq"] = newSeq
                    pointer[key_hash]["direct"] = "send"
                    return True, pointer

        # 提取上一次数据方向，并合并包数据
        if direct == pointer[key_hash]["direct"]:
            # 同方向， 源 -> 目的， ack不变， seq = seq + len
            # 判断seq大小
            send_seq = pointer[key_hash]["send_seq"]
            if seq - send_seq == pointer[key_hash]["seq"] + pointer[key_hash]["last_len"] and ack - pointer[key_hash]["ack_seq"]== pointer[key_hash]["ack"]:
                pointer[key_hash]["seq"] = seq - send_seq
                pointer[key_hash]["send_packet"] += 1
                pointer[key_hash]["send_len"] += length
                pointer[key_hash]["last_len"] = length
            else:
                print("丢包")
                return False, ""
        else:
            # 换方向， 源 -> 目的  seq = ack , ack = seq + len
            # 判断seq大小
            send_seq = pointer[key_hash]["send_seq"]
            last_seq = pointer[key_hash]["seq"]
            if seq - send_seq == pointer[key_hash]["ack"] and ack - pointer[key_hash]["ack_seq"] == last_seq + pointer[key_hash]["last_len"]:
                pointer[key_hash]["seq"] = pointer[key_hash]["ack"]
                pointer[key_hash]["ack"] = last_seq + pointer[key_hash]["last_len"]
                pointer[key_hash]["send_packet"] += 1
                pointer[key_hash]["send_len"] += length
                pointer[key_hash]["last_len"] = length
                pointer[key_hash]["direct"] = "send"
            else:
                print("丢包")
                return False, ""
    else:
        # 源地址等于初始目的地址，数据方向 目的 -> 源
        direct = "rec"
        # 提取上一次数据方向，并合并包数据
        if direct == pointer[key_hash]["direct"]:
            # 同方向， 目的 -> 源， ack不变， seq = seq + len
            # 判断seq大小
            ack_seq = pointer[key_hash]["ack_seq"]
            if seq - ack_seq == pointer[key_hash]["seq"] + pointer[key_hash]["last_len"] and ack - pointer[key_hash]["send_seq"] == pointer[key_hash]["ack"]:
                pointer[key_hash]["seq"] = seq - ack_seq
                pointer[key_hash]["rec_packet"] += 1
                pointer[key_hash]["rec_len"] += length
                pointer[key_hash]["last_len"] = length
            else:
                print("丢包")
                return False, ""
        else:
            # 换方向， 目的 -> 源 seq = ack , ack = seq + len
            # 判断seq大小
            ack_seq = pointer[key_hash]["ack_seq"]
            last_seq = pointer[key_hash]["seq"]
            if seq - ack_seq == pointer[key_hash]["ack"] and ack - pointer[key_hash]["send_seq"] == last_seq + pointer[key_hash]["last_len"]:
                pointer[key_hash]["seq"] = pointer[key_hash]["ack"]
                pointer[key_hash]["ack"] = last_seq + pointer[key_hash]["last_len"]
                pointer[key_hash]["rec_packet"] += 1
                pointer[key_hash]["rec_len"] += length
                pointer[key_hash]["last_len"] = length
                pointer[key_hash]["direct"] = "rec"
            else:
                print("丢包")
                return False, ""
    if func == "fin" and pointer[key_hash]["state"] == "estab":
        pointer[key_hash]["state"] = "fin1"
    elif func == "fin" and pointer[key_hash]["state"] == "fin1":
        pointer[key_hash]["state"] = "fin2"
    else:
        pass

    # print('func (%s) -> %s ' %  (func ,pointer))
    return True, pointer


pointer = {}
drop = {}
pr = PcapReader('/root/1.pcap')
counter = 1
while 1:
    try:
        pkt = pr.read_packet()[0]
        
    except:
        print('数据分析完成')
        break
    try:
        #if counter < 39 or counter > 40:
        #    counter += 1
        #    continue
        # 解析数据链路层数据
        timestamp = pkt.time
        # 解析网络层数据
        protocol = pkt['IP'].proto   # 6: TCP  17: UDP
        length = pkt['IP'].len - 20 - 20
        sip = pkt['IP'].src
        sip_value = convert_ip_to_number(sip)
        dip = pkt['IP'].dst
        dip_value = convert_ip_to_number(dip)

        if not protocol == 6:
            counter += 1
            continue

        # 解析TCP传输层数据
        sport = pkt['TCP'].sport
        dport = pkt['TCP'].dport
        flag = pkt['TCP'].flags
        seq = pkt['TCP'].seq
        ack = pkt['TCP'].ack
        options = pkt['TCP'].options
        print('-' * 60)
        print('counter :  %s'% counter)
        print('seq : ', seq)
        print('ack : ', ack)
        print('len : ', length)
        key_hash = sip_value ^ dip_value ^ sport ^ dport # 异或计算四元组哈希
        if not key_hash in drop:
            drop[key_hash] = []
        if flag == 'A':
            # 应答
            # print('ack')
            if pointer[key_hash]["state"] == 'estab':
                success, data = handle(pointer, key_hash, sip, seq, ack, length, options, "ack")
                if not success:
                    drop[key_hash].append({"sip": sip, "seq": seq, "ack": ack, "length": length, "options": options, "func": "ack"})
            elif pointer[key_hash]["state"] == 'fin2':
                success, data = handle(pointer, key_hash, sip, seq, ack, 1, options, "fin2")
                if not success:
                    drop[key_hash].append({"sip": sip, "seq": seq, "ack": ack, "length": 1, "options": options, "func": "fin2"})
                pointer[key_hash]["state"] = "close"
                pointer[key_hash]["etime"] = int(timestamp)
                pointer[key_hash]["last_len"] = 0
                pointer[key_hash]["continue"] = int(timestamp) - pointer[key_hash]["stime"]
                
            else:
                pass

            # 第三次握手 应答
            if pointer[key_hash]["state"] == 'ack send':
                if pointer[key_hash]["sip"] == sip:
                    # 源地址等于初始源地址，数据方向  源 -> 目的
                    pointer[key_hash]["send_packet"] += 1
                    last_ack = pointer[key_hash]["ack"]
                    last_seq = pointer[key_hash]["seq"]
                    pointer[key_hash]["seq"] = last_ack
                    pointer[key_hash]["ack"] = last_seq + 1
                    pointer[key_hash]["state"] = "estab"
                    pointer[key_hash]["direct"] = "send"
                if pointer[key_hash]["sip"] == dip:
                    # 目的地址等于初始源地址，数据方向  目的 -> 源
                    pass

        elif flag == 'S':
            # 开始第一次握手，请求建立连接
            # 初始化会话链，数据方向  源 -> 目的
            pointer[key_hash] = {
                                 "sip": sip, "dip": dip, "sport": sport, "dport": dport, "proto": "tcp",
                                 "send_len": 0, "rec_len": 0, "send_packet": 1, "rec_packet": 0,
                                 "state": "seq send", "last_len": 0, "seq": 0, "ack": 0, 
                                 "send_seq": seq, "direct": "send", "stime": int(timestamp), "etime": 0,
                                 "continue": 0, "drop": []
            }
            # time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        elif flag == 'SA':
            # 开始第二次握手，响应建立连接
            if pointer[key_hash]["sip"] == sip:
                # 源地址等于初始源地址，数据方向  源 -> 目的
                pass
            if pointer[key_hash]["sip"] == dip:
                # 目的地址等于初始源地址，数据方向  目的 -> 源
                last_seq = pointer[key_hash]["seq"]
                pointer[key_hash]["rec_packet"] = 1
                pointer[key_hash]["ack_seq"] = seq
                pointer[key_hash]["ack"] = last_seq + 1
                pointer[key_hash]["seq"] = 0
                pointer[key_hash]["state"] = "ack send"
                pointer[key_hash]["direct"] = "rec"
        elif 'P' in flag:   # 'P' or 'PA'
            # 开始传输数据并应答，存在应用层数据
            # print('psh ack')
            if pointer[key_hash]["state"] == 'estab':
                success, data = handle(pointer, key_hash, sip, seq, ack,  length, options, "psh")
                if not success:
                    drop[key_hash].append({"sip": sip, "seq": seq, "ack": ack, "length": length, "options": options, "func": "psh"})

        elif 'F' in flag:   # 'A' or 'FA'
            # 开始第一、二、三次挥手，响应断开连接
            # print('fin ack')
            if pointer[key_hash]["state"] in ['estab', 'fin1']:
                success, data = handle(pointer, key_hash, sip, seq, ack, 1, options, "fin")
                if not success:
                    drop[key_hash].append({"sip": sip, "seq": seq, "ack": ack, "length": 1, "options": options, "func": "fin"})

        elif 'R' in flag:  # 'R' or 'RA'
            # 重置连接并应答
            # print('rst ack')
            pointer.pop(key_hash)
            print('1111111111111111111')
            continue

        elif flag & 0x20 != 0:
            # 紧急数据
            print('urg')
        else:
            pass
        #print(pointer)
        for eachdrop in drop[key_hash]:
            print('---> 处理丢包')
            print(eachdrop)
            sip = eachdrop["sip"]
            seq = eachdrop["seq"]
            ack = eachdrop["ack"]
            length = eachdrop["length"]
            func = eachdrop["func"]
            options = eachdrop["options"]
            flag, data = handle(pointer, key_hash, sip, seq, ack, length, options, func)
            if flag:
                newNum = pointer[key_hash]["ack"]
                pointer[key_hash]["drop"].append(newNum)
                drop[key_hash].remove(eachdrop)
        #print(pointer)
        # print(options)
        counter += 1
    except Exception as e:
        #print(str(e))
        counter += 1
#print(json.dumps(pointer))
#print(len(pointer))
# # print(dlist)
#wrpcap('/root/2.pcap', dlist)
