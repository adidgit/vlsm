# vlsm
vlsm calculator




usage: vlsm.py [-h] [-v] CIDR num [num ...]

Variable Length Subneting

positional arguments:
  CIDR        CIDR notation i.e 192.168.1.10/24
  num         number of needed hosts per subnet (excluding network and
              broadcast address)

optional arguments:
  -h, --help  show this help message and exit
  -v          print detailed info for network and subnets)

Example of use: ./vlsm.py 192.168.1.0/24 10 10 100
