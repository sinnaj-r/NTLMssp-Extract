#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pyshark
output_format = input("Output-Format (0 => Hashcat; 1 => JTR) ")
path = input("Path for pcap > ")

cap = pyshark.FileCapture(path,display_filter="ntlmssp && http")
all_cor = {}
for pack in cap:
    try:
        if(pack.http):
            if(pack.http.ntlmssp_messagetype == "0x00000001"):
                if(pack.tcp.stream in all_cor):
                    all_cor[pack.tcp.stream]["hello"]=pack
                else:
                    all_cor[pack.tcp.stream] = {"hello":pack}
            elif(pack.http.ntlmssp_messagetype == "0x00000002"):
                if(pack.tcp.stream in all_cor):
                    all_cor[pack.tcp.stream]["challenge"]=pack
            elif(pack.http.ntlmssp_messagetype == "0x00000003"):
                if(pack.tcp.stream in all_cor):
                    all_cor[pack.tcp.stream]["auth"]=pack
    except Exception as e:
        pass
all_cor_keys = all_cor.keys()
all_cor_keys = sorted(all_cor_keys)
for k in all_cor_keys:
    curr_cor = all_cor[k]
    if(len(curr_cor) < 3):
        continue
    try:
        un = curr_cor["auth"].http.ntlmssp_auth_username
        ch = curr_cor["challenge"].http.ntlmssp_ntlmserverchallenge.replace(":","")
        domain = curr_cor["auth"].http.ntlmssp_auth_domain
        ntlm_all = curr_cor["auth"].http.ntlmssp_auth_ntresponse.replace(":","")
        ntlm_1 = ntlm_all[0:32]
        ntlm_2 = ntlm_all[32:]
        if(output_format == '1'):
            print(un+":$NETNTLMv2$"+domain+"$"+ch+"$"+ntlm_1+"$"+ntlm_2)
        else:
            print(un+"::"+domain+":"+ch+":"+ntlm_1+":"+ntlm_2)
    except:
        pass
