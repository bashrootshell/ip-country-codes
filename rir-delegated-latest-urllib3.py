#!/usr/bin/env python3

from sys import argv
from re import search
from math import log2
import urllib3
import ssl

"""
    Programmed with urllib3.
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
c_reqs = ssl.CERT_NONE
urllib3.disable_warnings()

h = urllib3.PoolManager(
    cert_reqs=c_reqs)

RIRs = ("https://ftp.lacnic.net/pub/stats/ripencc/delegated-ripencc-latest",
        "https://ftp.lacnic.net/pub/stats/apnic/delegated-apnic-latest",
        "https://ftp.lacnic.net/pub/stats/arin/delegated-arin-extended-latest",
        "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
        "https://ftp.lacnic.net/pub/stats/afrinic/delegated-afrinic-latest")


if len(argv) > 1:
    for url in RIRs:
        # reads content from URLs one by one
        for prefix in h.request('GET', url).data.decode('utf-8').splitlines():
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
