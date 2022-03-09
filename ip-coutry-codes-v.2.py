#!/usr/bin/env python

from sys import argv
from re import search
from math import log2
from urllib3 import disable_warnings, PoolManager
from ssl import CERT_NONE

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

disable_warnings()

httpreq = PoolManager(
    cert_reqs=CERT_NONE)

CC = argv[1] if len(argv) == 2 else exit("Provide a country code \
eg: US or CA")

RIPENCC = ("https://ftp.lacnic.net/pub/stats/ripencc/delegated-ripencc-latest")
APNIC = ("https://ftp.lacnic.net/pub/stats/apnic/delegated-apnic-latest")
ARIN = ("https://ftp.lacnic.net/pub/stats/arin/delegated-arin-extended-latest")
LACNIC = ("https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest")
AFRINIC = ("https://ftp.lacnic.net/pub/stats/afrinic/delegated-afrinic-latest")

CC_RIPE = ("AL", "AD", "AM", "AT", "AZ", "BH", "BY", "BE", "BA", "BG", "HR",
"CY", "CZ", "DK", "EE", "FO", "FI", "FR", "GE", "DE", "GI", "GR", "GL", "GG",
"VA", "HU", "IS", "IR", "IQ", "IE", "IM", "IL", "IT", "JE", "JO", "KZ", "KW",
"KG", "LV", "LB", "LI", "LT", "LU", "MT", "MD", "MC", "ME", "NL", "MK", "NO",
"OM", "PS", "PL", "PT", "QA", "RO", "RU", "SM", "SA", "RS", "SK", "SI", "ES",
"SJ", "SE", "CH", "SY", "TJ", "TR", "TM", "UA", "AE", "GB", "UZ", "YE", "AX")

CC_APNIC = ("AF", "AS", "AU", "BD", "BT", "IO", "BN", "KH", "CN", "CX", "CC",
"CK", "FJ", "PF", "TF", "GU", "HK", "IN", "ID", "JP", "KI", "KP", "KR",
"LA", "MO", "MY", "MV", "MH", "FM", "MN", "MM", "NR", "NP", "NC",
"NZ", "NU", "NF", "MP", "PK", "PW", "PG", "PH", "PN", "WS", "SG",
"SB", "LK", "TW", "TH", "TL", "TK", "TO", "TV", "VU", "VN", "WF")

CC_ARIN = ("AI", "AQ", "AG", "BS", "BB", "BM", "BV", "CA", "KY",
"DM", "GD", "GP", "HM", "JM", "MQ", "MS", "PR", "BL", "SH", "KN",
"LC", "MF", "PM", "VC", "TC", "UM", "US", "VG", "VI", "SM")

CC_LACNIC = ("AR", "AW", "BZ", "BO", "BQ", "BR", "CL", "CO", "CR", "CU", "CW",
"DO", "EC", "SV", "FK", "GF", "GT", "GY", "HT", "HN", "MX", "NI", "PA", "PY",
"PE", "SX", "GS", "SR", "TT", "UY", "VE")

CC_AFRINIC = ("DZ", "AO", "BJ", "BW", "BF", "BI", "CM", "CV", "CF",
"TD", "KM", "CG", "CD", "CI", "DJ", "EG", "GQ", "ER", "SZ", "ET",
"GA", "GM", "GH", "GN", "GW", "KE", "LS", "LR", "LY", "MG", "MW", "ML",
"MR", "MU", "YT", "MA", "MZ", "NA", "NE", "NG", "RE", "RW", "ST", "SN",
"SC", "SL", "SO", "ZA", "SS", "SD", "TZ", "TG", "TN", "UG", "EH", "ZM", "ZW")

if CC in CC_RIPE:
    url = RIPENCC
elif CC in CC_APNIC:
    url = APNIC
elif CC in CC_ARIN:
    url = ARIN
elif CC in CC_LACNIC:
    url = LACNIC
elif CC in CC_AFRINIC:
    url = AFRINIC
else:
    exit(f'The country code {CC} in invalid.')

for prefix in httpreq.request('GET', url).data.decode('utf-8').splitlines():
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
