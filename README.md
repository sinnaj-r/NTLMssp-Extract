# NTLMssp-Extract
A small Python-Script to extract NetNTLMv2 Hashes from NTMLssp-HTTP-Authentications, which were captured in a pcap.

Requires **pyshark** (https://github.com/KimiNewt/pyshark) and **Python 2.7**

#Installation:
Just clone this repository and run the *ntlmssp_extract.py*  file.

#Usage:
After executing the python-file, you can choose which output format you want, *0* for (cuda/ocl)[Hashcat](https://hashcat.net/hashcat/) or *1* for [JohnTheRipper](http://www.openwall.com/john/)
Then you are able to enter the full path of your capture-file (if you want to speed up the extraction, you should remove all the non related packages from the capture before you run NTLMssp-Extract).
    
###Todos:
 *	pass path and format via command line parameters
 * filter out corrupt/invalid hashes & packages


###Contributing:
While I think the script does the job, which it was written for, quite good, I'm always open to new ideas and/or pull requests & issues!