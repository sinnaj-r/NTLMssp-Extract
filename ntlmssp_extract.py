#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pyshark
import argparse

parser = argparse.ArgumentParser(description="extract NetNTLMv2 hashes from pcap file")
parser.add_argument("-f", metavar="format", type=int, help="output format (0 => Hashcat; 1 => JTR)")
parser.add_argument("-p", metavar="pcap", help="pcap file path")
args = parser.parse_args()

if args.f in [0, 1]:
    output_format = args.f
else:
    output_format = input("Output-Format (0 => Hashcat; 1 => JTR) ")

if args.p:
    path = args.p
else:
    path = input("Path for pcap > ")

cap = pyshark.FileCapture(path,display_filter="ntlmssp")
all_cor = {}
for pack in cap:
    if "<HTTP " in str(pack.layers):
        data = pack.http
    elif "<SMB " in str(pack.layers):
        data = pack.smb
    elif "<SMB2 " in str(pack.layers):
        data = pack.smb2
    if data:
        try:
            if(data.ntlmssp_messagetype == "0x00000002"):
                if(pack.tcp.stream in all_cor):
                    all_cor[pack.tcp.stream]["challenge"]=data.ntlmssp_ntlmserverchallenge.replace(":","")
                else:
                    all_cor[pack.tcp.stream] = {"challenge":data.ntlmssp_ntlmserverchallenge.replace(":","")}
            elif(data.ntlmssp_messagetype == "0x00000003"):
                if(pack.tcp.stream in all_cor):
                    all_cor[pack.tcp.stream]["username"]=data.ntlmssp_auth_username
                    if data.ntlmssp_auth_domain == "NULL":
                        all_cor[pack.tcp.stream]["domain"]=""
                    else:
                        all_cor[pack.tcp.stream]["domain"]=data.ntlmssp_auth_domain
                    all_cor[pack.tcp.stream]["ntlm_1"]=data.ntlmssp_auth_ntresponse.replace(":","")[0:32]
                    all_cor[pack.tcp.stream]["ntlm_2"]=data.ntlmssp_auth_ntresponse.replace(":","")[32:]
        except Exception as e:
            pass
all_cor_keys = all_cor.keys()
all_cor_keys = sorted(all_cor_keys)
for k in all_cor_keys:
    curr_cor = all_cor[k]
    if(len(curr_cor) != 5):
        continue
    try:
        un = curr_cor["username"]
        ch = curr_cor["challenge"]
        domain = curr_cor["domain"]
        ntlm_1 = curr_cor["ntlm_1"]
        ntlm_2 = curr_cor["ntlm_2"]
        if(output_format == '1'):
            print(un+":$NETNTLMv2$"+domain+"$"+ch+"$"+ntlm_1+"$"+ntlm_2)
        else:
            print(un+"::"+domain+":"+ch+":"+ntlm_1+":"+ntlm_2)
    except:
        pass
