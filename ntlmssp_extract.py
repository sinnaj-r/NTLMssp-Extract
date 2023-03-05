#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pyshark
import argparse

def main():
    parser = argparse.ArgumentParser(description = "extract NetNTLMv2 hashes from pcap file")
    parser.add_argument("-f", metavar="format", type = int, help = "output format (0 => Hashcat; 1 => JTR)")
    parser.add_argument("-p", metavar="pcap", help = "pcap file path")
    args = parser.parse_args()

    if args.f in [0, 1]:
        output_format = args.f
    else:
        output_format = input("Output-Format (0 => Hashcat; 1 => JTR) ")

    if args.p:
        path = args.p
    else:
        path = input("Path for pcap > ")

    try:
        cap = pyshark.FileCapture(path, display_filter = "ntlmssp")
    except FileNotFoundError as e:
        print(e)
        exit(1)

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
                    if(pack.tcp.stream not in all_cor):
                        all_cor[pack.tcp.stream] = {}
                    all_cor[pack.tcp.stream]["challenge"] = data.ntlmssp_ntlmserverchallenge.replace(":", "")
                elif(data.ntlmssp_messagetype == "0x00000003"):
                    if(pack.tcp.stream not in all_cor):
                        all_cor[pack.tcp.stream] = {}
                    all_cor[pack.tcp.stream]["username"] = data.ntlmssp_auth_username
                    if data.ntlmssp_auth_domain == "NULL":
                        all_cor[pack.tcp.stream]["domain"] = ""
                    else:
                        all_cor[pack.tcp.stream]["domain"] = data.ntlmssp_auth_domain
                    all_cor[pack.tcp.stream]["response"] = data.ntlmssp_auth_ntresponse.replace(":", "")
            except Exception as e:
                pass

    all_cor_keys = all_cor.keys()
    all_cor_keys = sorted(all_cor_keys)
    for k in all_cor_keys:
        curr_cor = all_cor[k]
        if(len(curr_cor) != 4):
            continue
        try:
            un = curr_cor["username"]
            ch = curr_cor["challenge"]
            domain = curr_cor["domain"]
            ntlm_1 = curr_cor["response"][:32]
            ntlm_2 = curr_cor["response"][32:]
            if(output_format == '1'):
                print(un + ":$NETNTLMv2$" + domain + "$" + ch + "$" + ntlm_1 + "$" + ntlm_2)
            else:
                print(un + "::" + domain + ":" + ch + ":" + ntlm_1 + ":" + ntlm_2)
        except:
            pass

if __name__ == "__main__":
    main()
