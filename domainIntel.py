#!/usr/bin/python3.10


from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver import ActionChains
from selenium.webdriver.common.actions.action_builder import ActionBuilder
from selenium.webdriver.common.actions.mouse_button import MouseButton
from signal import signal, SIGINT
from os.path import exists
from termcolor import colored
import os
import re
import sys
import argparse

options = Options()
options.add_argument("-headless")
options.page_load_strategy = 'eager'
pattern = '^([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,3}[A-Za-z]{2,6}$'

def handler(signal_received, frame):
	# Handle any cleanup here
	print('SIGINT or CTRL-C detected. Exiting gracefully')
	driver.quit()
	exit(0)

def document_initialised(driver):
	return driver.execute_script("return initialised")


def parseLine(line):
	global ASN
	for field in line:
		if re.match('^Latest*', field):
			re.sub(r'Latest', '', field)
		if re.match('^Performance*', field):
			re.sub(r'Performance', '', field)
		elif re.match('^IP range', field):
			print("\n")
			print("##########################")
			print("\n")
			print(field, end=' ')
		else:
			print(field, end=' ')
			if re.match("^AS", field):
				ASN = field
				print(ASN)


def parseLine2(line):
	u=''
	for field in line:
		u+=field
	return("https://sitereport.netcraft.com/?url=http://" + u)



def browse(el):
	print("Processing ...", file=sys.stderr)
	for webEl in el:
		subElements = webEl.find_elements(By.TAG_NAME, "tr");
		for r in subElements:
			line = (r.get_attribute('innerText')).splitlines()
			parseLine(line)
			print("\n")


def browsePeeringDB(el):
	for r in el:
		print("#############")
		line = (r.get_attribute('innerText')).splitlines()
		parseLine(line)
		print("\n")
	print("\n")


def browseReports(el):
	l = []
	for r in el:
		line = (r.get_attribute('innerText')).replace(" ", "").replace("\n","") #splitlines()
		l.append(parseLine2(line))
	return l


def browsePeers(el):
	l=''
	j=0
	for item in el:
		if j<2:
			l = l + ' ' + item
			j=j+1
		else:
			print(l)
			l=''
			j=0



def driverInit(driver):
	driver.set_window_position(0, 0)
	driver.set_window_size(640, 640)
	driver.implicitly_wait(2)


#PART 1
def domainInfo(domain):

	driver = webdriver.Firefox(options=options)
	driverInit(driver)

	query = "https://searchdns.netcraft.com/?restriction=site+contains&host=" + domain + "&position=limited"
	print(query)
	driver.get(query)

	try:
 		center = driver.find_element(By.XPATH, "//h2[@class='center']")
 		fout.write("Nothing for this domain on Netcraft" + "\n")
 		print("Nothing for this domain on Netcraft")

	except:
		print()
	try:
		netInfo = driver.find_elements(By.ID, "network_table_section")
		print(netInfo)
	except:
		driver.close()
		driver.quit()
		return -1


	with open('./report.txt', 'a') as  f:
		sys.stdout = f
		print("\t\t #######  http://" + domain + " #######\n\n")
		browse(netInfo)

		try:
			#ASN = ASN
			print("\n\n")
			print("################ " + ASN + ' IXP ##################')
			print("\n\n")
			global nextQuery
			nextQuery = "https://www.peeringdb.com/search?q=" + ASN
		except:
			print("Failed to get ASN field", file=sys.stderr)
			sys.stdout = sys.__stdout__
			f.close()
			driver.close()
			driver.quit()
			exit()

		sys.stdout = sys.__stdout__
		f.close()
		driver.close()
		driver.quit()




def subdomainInfo():

	driver1 = webdriver.Firefox(options=options)
	driverInit(driver1)

	query = "https://searchdns.netcraft.com/?restriction=site+contains&host=" + subDom + "&position=limited"

	try:
		driver1.get(query)

		reports = driver1.find_elements(By.XPATH, "//a[@class='results-table__host']")
		rapports = browseReports(reports)
		for rap in rapports:
			print(rap)

	except:
		print("error getting data", file=sys.stderr)
		driver1.close()
		driver1.quit()
		return -1


	with open('./report.txt', 'a') as  f:
		sys.stdout = f

		try:
			print("\n\n")
			print("\t################ " + subDom + ' SUBDOMAINS RAPPORT(s) ##################')
			print("\n\n")
			for rap in rapports:
				print(rap)
		except:
			print("Failed to write subdomains info", file=sys.stderr)
			'''sys.stdout = sys.__stdout__
			f.close()
			driver.close()'''

		sys.stdout = sys.__stdout__
		f.close()
		driver1.close()
		driver1.quit()


#PART2

def peeringBasicInfo():

	driver2 = webdriver.Firefox(options=options)
	driverInit(driver2)

	driver2.get(nextQuery)

	'''
	try:
		wait = WebDriverWait(driver, 10).until(EC.title_contains('AS'))
	finally:
		print("done")
	'''
	try:
		elLeft = driver2.find_elements(By.XPATH, "//div[@class='row view_row  ']")
	except:
		driver2.close()
		driver2.quit()
		return -1

	with open('./report.txt', 'a') as  f:
		sys.stdout = f
		browsePeeringDB(elLeft)

		sys.stdout = sys.__stdout__

		f.close()
		driver2.close()
		driver2.quit()

#PART3

def peeringIXPInfo():

	driver3 = webdriver.Firefox(options=options)
	driverInit(driver3)

	driver3.get(nextQuery)
	try:
		IXP = driver3.find_elements(By.XPATH, "//div[@class='row item operational']")
	except:
		driver3.close()
		driver3.quit()
		return -1

	with open('./report.txt', 'a') as  f:
		sys.stdout = f
		print("\n\n\t\t################ " + ASN +" IXP Connections ############### \n\n")
		browsePeeringDB(IXP)

		sys.stdout = sys.__stdout__

		f.close()
		driver3.close()
		driver3.quit()

#PART4
def peeringPeersInfo():

	driver4 = webdriver.Firefox(options=options)
	driverInit(driver4)

	#print(nextQuery)
	driver4.get(nextQuery)

	try:
		peers = driver4.find_element(By.ID, "list-facilities")
		items = (peers.get_attribute('innerText')).splitlines()
		#items = (peers.get_attribute('innerText')).splitlines()

		j=0
		line=''

		cleanItems = list(filter((items[1]).__ne__,items)) #remove current ASN from list

		#print(peers.get_attribute('innerText'))
	except:
		print("issue while processing peers")
		driver4.close()
		driver4.quit()
		return -1

	try:
		#print("About to write in file\n")
		with open('./report.txt', 'a') as  f:
			sys.stdout = f
			print("\n\n\t\t################ " + ASN +" PEERING InterConnections ############### \n\n")
			browsePeers(cleanItems)

			sys.stdout = sys.__stdout__

			f.close()
			driver4.close()
			driver4.quit()
	except:
		print("error writing in file")

		f.close()
		driver4.close()
		driver4.quit()

#part 5
def asnInfo():
	with open('./report.txt', 'a') as f:
		sys.stdout = f

		try:
			#ASN = ASN
			print("\n\n")
			print("################ " + ASN + ' Basic Information ##################')
			print("\n\n")
			global nextQuery
			nextQuery = "https://www.peeringdb.com/search?q=" + ASN
		except:
			print("Failed to write inf file", file=sys.stderr)
			sys.stdout = sys.__stdout__
			f.close()
			driver.close()
			driver.quit()
			exit()

	sys.stdout = sys.__stdout__
	f.close()
	driver.close()
	driver.quit()

if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument("-d", "--domain", help="domain to query (ex: ./domainIntel.py -d www.x.com)")
	parser.add_argument("-s", "--subdomain", help="subdomains to query (ex: ./domainIntel.py -s *.sfr.fr)")
	parser.add_argument("-pb", "--peeringBasicInfo",action="store_true", help="Get basic info about the domain's AS")
	parser.add_argument("-i", "--peeringIXPInfo", action="store_true", help="Get Exchange Point for the domain's AS")
	parser.add_argument("-o", "--peeringPeersInfo", action="store_true", help="Get Peers for the domain's AS")
	parser.add_argument("--asn", help="Get info about AS (ex: ./domainIntel.py --asn ASNXXXX)")
	parser.add_argument("-a" ,"--all", action="store_true", help="Get all info about domain and hosting AS")
	args = parser.parse_args()

	driver = webdriver.Firefox(options=options)

	# Tell Python to run the handler() function when SIGINT is recieved
	signal(SIGINT, handler)

	print('Running. Press CTRL-C to exit.')

	if (exists("./report.txt")):
		os.remove("./report.txt")

	if args.domain:
		domain = args.domain
		'''		result = re.match(pattern, domain)
		out = ''

		if not(result):
			print("" + domain + " is Not a valid Domain")
			exit(1)
		else:
			print("VALID DOMAIN")
		'''
		domainInfo(domain)

		if args.peeringBasicInfo:
			peeringBasicInfo()
		elif args.peeringIXPInfo:
			peeringIXPInfo()
		elif args.peeringPeersInfo:
			peeringPeersInfo()
		elif args.all:
			peeringBasicInfo()
			peeringIXPInfo()
			peeringPeersInfo()

	elif args.subdomain:
		#global domain
		#domain = input("Enter the domain you want to make a Netcraft query on (format => *.sfr.fr): ")
		global subDom
		subDom = args.subdomain
		subdomainInfo()
		
	elif args.asn:
		global ASN
		ASN = args.asn
		asnInfo()
		peeringBasicInfo()
		peeringIXPInfo()
		peeringPeersInfo()
	else:
		domain = input("Enter the domain you want to make a Netcraft query on: ")

		result = re.match(pattern, domain)
		out = ''

		if not(result):
			print("" + domain + " is Not a valid Domain")
			exit(1)
		else:
			print("VALID DOMAIN")

		domainInfo(domain)

		if args.peeringBasicInfo:
			peeringBasicInfo()
		elif args.peeringIXPInfo:
			peeringIXPInfo()
		elif args.peeringPeersInfo:
			peeringPeersInfo()
		elif args.all:
			peeringBasicInfo()
			peeringIXPInfo()
			peeringPeersInfo()


	print(colored('$ cat report.txt to read report', 'green'))
	exit()
