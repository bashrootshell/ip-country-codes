#!/usr/bin/env python3

from sys import argv
from re import search
from math import log2
from urllib.request import urlopen
import ssl

"""
    Programmed with urllib.
    Global RIR IPv4 CIDR prefix extractor, by country.
    It now searches for a particular CC in all RIRs:
    RIPE NCC, APNIC, ARIN, LACNIC and AFRINIC

    Usage: ./program.py countrycode (optional: file)
    If a file isn't an argument, it prints prefixes to stdout.

    PEP8 compliant
    "Explicit is better than implicit."
    — The Zen of Python
"""

"""  Bypass SSL/TLS checks  """
ct = ssl.create_default_context()
ct.check_hostname = False
ct.verify_mode = ssl.CERT_NONE

RIRs = ["https://ftp.lacnic.net/pub/stats/ripencc/delegated-ripencc-latest",
        "https://ftp.lacnic.net/pub/stats/apnic/delegated-apnic-latest",
        "https://ftp.lacnic.net/pub/stats/arin/delegated-arin-extended-latest",
        "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
        "https://ftp.lacnic.net/pub/stats/afrinic/delegated-afrinic-latest"]

if len(argv) > 1:
    for url in RIRs:
        for prefix in urlopen(url, context=ct).read().\
                decode('utf-8').split():  # reads content from URLs one by one
            regex = search(str(argv[1]) + '.*ipv4', prefix)
            if regex:  # searches for cc and ipv4 strings
                netaddr = prefix.split("|")[3]  # net addr
                bitmask = int(prefix.split("|")[4])  # bits used by net addr
                cidrmask = int(32 - log2(bitmask))  # converts bits into CIDR
                if len(argv) == 2:
                    print(f'{netaddr}/{cidrmask}')  # prints to stdout
                elif len(argv) == 3:
                    with open(f'{argv[2]}.txt', 'a') as file:
                        print(f'{netaddr}/{cidrmask}', file=file)
else:
    print('Please provide at least a universal country code. (Optional: a\
 filename descriptor to save the results.)\n\
 Ex: ./program.py GB (print to stdout) OR ./program.py GB ipaddr-gb.txt \
 (write to file "ipaddr-gb.txt" as an example)')
