# domainAndPeeringIntel
Python3.10 + Selenium information extracter for searchdns.netcraft.com and peeringdb.com

# help

usage: domainIntel.py [-h] [-d DOMAIN] [-s SUBDOMAIN] [-pb] [-i] [-o] [--asn ASN] [-a]

  -h, --help            show this help message and exit
  
  -d DOMAIN, --domain DOMAIN  domain to query (ex: ./domainIntel.py -d www.x.com)
  
  -s SUBDOMAIN, --subdomain SUBDOMAIN  subdomains to query (ex: ./domainIntel.py -s *.sfr.fr)
  
  -pb, --peeringBasicInfo  Get basic info about the domain's AS
  
  -i, --peeringIXPInfo  Get Exchange Point for the domain's AS
  
  -o, --peeringPeersInfo  Get Peers for the domain's AS
  
  --asn ASN             Get info about AS (ex: ./domainIntel.py --asn ASNXXXX)
  
  -a, --all             Get all info about domain and hosting AS
  

# requirements

Selenium => https://www.selenium.dev/documentation/webdriver/getting_started/install_library/

termcolor => https://pypi.org/project/termcolor/
