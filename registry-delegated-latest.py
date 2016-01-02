#!/usr/bin/env python
""" PEP8 compliant """

import sys
import re
import math
import urllib2


""" IANA Registry CIDR prefix extractor by country. """
""" Not intended for end users: expect a clean and fast code. """


__author__ = 'bashrootshell'
__license__ = 'BSD New'
__version__ = '1.1'
__status__ = 'Production'

""" Usage: ./program.py URL countrycode (optional: file)
If a file isn't an argument, print prefixes to stdout. """

if sys.argv[1:]:
    try:
        with open(sys.argv[3], 'w'):
            pass
    except:
        pass
    for prefix in urllib2.urlopen(sys.argv[1], None, 5.0):
        regex = re.search(str(sys.argv[2]) + '.*ipv4', prefix)
        if regex:
            netaddr = prefix.split('|')[3]
            bits = int(prefix.split('|')[4])
            mask = int(32 - math.log(bits, 2))
            if len(sys.argv) == 4:
                with open(sys.argv[3], 'a') as file:
                    file.write('{}/{}\n'.format(netaddr, mask))
            elif len(sys.argv) == 3:
                print '{}/{}'.format(netaddr, mask)
else:
    sys.exit('Provide a valid URL and a country code.')
