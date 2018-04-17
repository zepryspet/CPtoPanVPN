#!/usr/bin/env python3
import re
import ipaddress


#Variables to modify#
Ext_IF = 'ethernet1/1' #External interface to setup the VPNs, 
Ext_IF_Netmask = '24'	#External interface IP address netmask to setup the VPNs, 
Tunnel_start = 1 #It'll create tunnels from tunnel.1 modify if you want to start on a different tunnel number.

#Don't modify antything below#

#Debug Output
DGW = False #Debug gateway and IPs
Dvpn =	False #Debug VPN settings
Dproxy = False #debug proxy

#Global Variables#
VPN_List = []	#A list to store all the VPN setiings.
Gateway_List = [] #A list to store all the Gateway objects.
Proxy_List = [] #A list to store all Proxy IDs

def ParseVPN():
	## Open the file that contains the VPNs
	file = open('objects_5_0.C')
	## Read the first line 
	line = file.readline()
	## If the file is not empty keep reading line one at a time
	## till the file is empty

	#Detecting start of VPN section
	tab = 0						#Variable used to check the identation level of the VPN section
	while line:
		if ':communities (' in line:
			tab = line.count("\t")		#the closing parenthesis should be at the identation same level
			break						#Breaking the loop when the section is detected
		line = file.readline()

	##Variables###
	VPN_linestart = ("\t"*(tab+1))+ ': ('
	VPN_Name = ''
	GW_List = [] 
	DHG_List = [] 
	#Lines to look for to get the VPN parameters when the parameter is in the same line
	VPN_search = [':ike_p1_enc_alg',':ike_p1_hash_alg',':ike_p1_rekey_time', ':ike_p1_use_aggressive (', ':ike_p1_use_shared_secret (', ':ike_p2_enc_alg', ':ike_p2_hash_alg', ':ike_p2_use_rekey_kbytes', ':ike_p2_rekey_time', ':ike_p2_use_pfs', ':tunnel_granularity']
	#Looking for parameters outside the same text line
	DHG_search = [':ike_p1_dh_grp',':ike_p2_pfs_dh_grp'] 
	Gateway_search = ':participant_gateways'
	Sattelite_search = ':satellite_gateways'
	Aux = ['']*11		#Auxiliar variable to temporarly store the VPN parameters

	#Reading the VPN section
	line = file.readline()
	while line:
		if line.startswith (VPN_linestart):									
			VPN_Name = line.strip(VPN_linestart).rstrip()
			if VPN_Name != 'MyIntranet' and VPN_Name != 'RemoteAccess' and VPN_Name != 'MyExtranet':
				#Reading VPN parameters
				del DHG_List [:] #Clearing the DH variable after every VPN read
				del GW_List [:] #Clearing gateway list
				while line:	
					#Reading DH Group for Phase 1&2
					for parameter in DHG_search:
						if parameter in line:
							while line:
								if 'Name' in line:
									DHG_List.append(FindBetween(line))
								if line.startswith(("\t"*(tab+3)) + ')'):	#breaking while loop after reaching the end of the diffie helman section
									break
								line = file.readline()
					#Reading VPN paramaters
					for index, parameter in enumerate(VPN_search):
						if parameter in line:
							Aux[index] = FindBetween(line)	
					#Reading gateway names	
					if (Gateway_search in line or Sattelite_search in line) and ('()' not in line  ):
						#print (line)
						while line:
							if 'Name' in line:
								GW_List.append(FindBetween(line))
							if SectionEnd(line, (tab+2)):	#breaking while loop after reaching the end of the gateway list
								break
							line = file.readline()
					if line.startswith(("\t"*(tab+1)) + ')'):	#breaking while loop after reaching the end of the current VPN
						break
					line = file.readline()
				VPN_List.append(VPN(VPN_Name, DHG_List, Aux, GW_List))	
				
		#Detection closing parenthesis of VPN section and breaking loop if we reach it.
		if line.startswith(("\t"*tab) + ')'):
			break
		line = file.readline()	
		
	file.close() #closing file		
	
def ParseGateway():
	## Open the file that contains the VPNs
	file = open('objects_5_0.C')
	## Read the first line 
	line = file.readline()
	while line:
		tabs = 0
		ip = Proxy_ID = ''
		for vpn in VPN_List:
			for gateway in vpn.gateways:
				if ObjectCheck (line, gateway):
					tabs=line.count('\t') #Detecting indentation level to stop parsing at the closing parenthesis
					while line:			#Detecting gateway type
						if ':ClassName (gateway_plain)' in line:		#Remote gateway type
							while line:			 #continue reading the file until the IP address is detected
								if ':ipaddr (' in line:
									ip = FindBetween(line)
								if ':manual_encdomain (ReferenceObject' in line:
									tabs2 = line.count('\t')
									while line:
										if 'Name (' in line:
											Proxy_ID = FindBetween(line)
										if line.startswith(("\t"*tabs2) + ')'):	#breaking while loop after reaching the end of the current section
											break
										line = file.readline()
								if line.startswith(("\t"*tabs) + ')'):	#breaking while loop after reaching the end of the current gateway
									Gateway_List.append(Gateways (gateway, ip , False, Proxy_ID)) 
									break
								line = file.readline()
						if ':ClassName (gateway_ckp)' in line or ':ClassName (gateway_cluster)' in line:			#Local gateway type
							#print (gateway)
							while line:			 #continue reading the file until the IP address of the interface leading to the internet is detected
								if ':ipaddr (' in line:
									tmp = line		#temp store for the checkpoint interfaces	
								if ':leads_to_internet (true)' in line:
									#print (tmp)		#Only if the interface leds to the internet print it.
									ip = FindBetween(tmp)
								if ':manual_encdomain (ReferenceObject' in line and '()' not in line:
									tabs2 = line.count('\t')
									while line:
										if 'Name (' in line:
											Proxy_ID = (FindBetween(line))
										if line.startswith(("\t"*tabs2) + ')'):	#breaking while loop after reaching the end of the current section
											break
										line = file.readline()
								if line.startswith(("\t"*tabs) + ')'):	#breaking while loop after reaching the end of the current gateway
									Gateway_List.append(Gateways (gateway, ip , True, Proxy_ID)) 
									break
								line = file.readline()
						if line.startswith(("\t"*tabs) + ')'):	#breaking while loop after reaching the end of the current gateway
							break
						line = file.readline()
		line = file.readline()
	file.close() #closing file

#Parsing the encryption domain, detecting if it's a group, network or host.	
def ParseProxy(Object_List):
	## Open the file that contains the VPNs
	file = open('objects_5_0.C')
	## Read the first line 
	line = file.readline()
	Proxy_ID = []
	while line:
		for object_name in Object_List:
			#print (gateway.proxy_id)
			if object_name != '' and ObjectCheck (line, object_name):
				#Detecting indentation level to stop parsing at the closing parenthesis
				tabs=line.count('\t') 
				#Initializing variables
				isSupported = True
				isGroup= False
				ipaddr = ''
				netmask= ''
				del Proxy_ID [:]
				
				#Reading Object section
				while line:		
					#Detecting if the object is non-supported or if it's an object group.
					if ':ClassName (network_object_group)' in line:		#Proxy-iD is a group of objects
						isGroup= True
					if ':ClassName (address_range)' in line or ':ClassName (group_with_exception)' in line:		#Non-supported classnames
						isSupported = False
					#Extracting	the values for hosts and networks
					if 	not isGroup and isSupported and ':ipaddr (' in line:
						ipaddr = FindBetween(line)
					if 	not isGroup and isSupported and ':netmask (' in line:
						netmask = FindBetween(line)
					if isGroup and ': (ReferenceObject' in line:				#Read next 3 lines and get the name.
						for i in range (3):
							line = file.readline()
							if ':Name (' in line:
								Proxy_ID.append (FindBetween(line))
					if line.startswith(("\t"*tabs) + ')'):	#breaking while loop after reaching the end of the current object
						#Creating objects before ending the loop
						if isGroup:
							Proxy_List.append (ProxyID (object_name, isSupported, isGroup, Proxy_ID))
						if not isGroup and isSupported and netmask == '':		#Proxy is host
							Proxy_List.append (ProxyID (object_name, isSupported, isGroup, str(ipaddress.IPv4Network(ipaddr + '/32'))))
						if not isGroup and isSupported and netmask != '':		#Proxy is network
							Proxy_List.append (ProxyID (object_name, isSupported, isGroup, str(ipaddress.IPv4Network(ipaddr + '/' +netmask))))
						break
					line = file.readline()
		line = file.readline()
	#If there're still object groups with with object members that hasn't been added to the proxy list do it until all object groups are completed.
	file.close()
	missingObj =[]
	for child in Proxy_List:
		if child.isGroup:
			if not child.isCompleted:
				missingObj += child.proxy_id
				child.isCompleted = True
	if len(missingObj) != 0:
		ParseProxy(missingObj)
	del missingObj [:]
		
		
def ObjectCheck(line, object_name):
	aux = line.rstrip().strip('\t:').strip().strip('\(')	#removing starting parenthesis, tabs, spaces, 
	if object_name == aux:										#If the line matches a gateway name return true
		return True
	else:
		return False

#Extract a parameter from a text line.
def FindBetween (line):
	if line.count('(') == 1 :		#Find text between a single parenthesis
		result = re.search('\((.*)\)', line)
		return result.group(1)
	else:
		result = re.search('Group\s(.*)\(', line) #Exception for DH group PH 1&2 -2 parenthesis-
		return result.group(1)

#Check and return True if the line is the end of the subsection or the starting of the next on and return True 
def SectionEnd(line, tab):
	if line.startswith (("\t"*tab)  + ')'):
		return True
	else:
		return False

#Extracting local gateway name
def LocalGateway ():
	lgw = 0
	for obj in Gateway_List:
		if obj.local:
			lgw += 1

	if lgw != 1:
		print ("More than 1 local gateway detected, please select the number of desired firewall")
		print ("number\tgateway name\t ip address")
		lgw = 1
		for obj in Gateway_List:
			if obj.local:
				print (str(lgw) + "\t"+obj.name + "\t"+obj.ip+"\n")
				lgw += 1
		lwgNumber = int(input("Selected firewall:\t"))
		lgw = 1
		for obj in Gateway_List:
			if obj.local:
				if lgw == int(lwgNumber):
					return obj.name
				lgw += 1	
	if lgw ==1:
		for obj in Gateway_List:
			if obj.local:
				return obj.name
	else:
		return ''

def VPNSettings(LGateway):
	#Dictionary to translate the extracted VPN parameters to the PA xml set format.
	dictionary = {'AES-256': 'aes-256-cbc', 'AES-128': 'aes-128-cbc', '3DES':'3des','SHA1': 'sha1', 'MD5':'md5','2 ': 'group2', "5 ": 'group5'}
	f = open('warnings.txt', 'w')	
	set_commands = open('set_crypto.txt', 'w')	#File to store the set commands for the vpns
	for obj in VPN_List:
		#Parsing only the VPNs with the selected local gateway. 
		if LGateway in obj.gateways:
			############################
			#####Generating warnings####
			############################
			#don't migrate VPN communities with less than 2 gateways and genarate a warning.
			if len(obj.gateways) <2:
				f.write ("Less than 2 gateways detected in a community, analyze if it needs to be migrated. Community name: " + obj.name + "\n")
			#Generate a warning when more than 2 gateways are detected in a community
			if len(obj.gateways) >2:
				f.write ("Community with more than 2 gateways if this is a star community some VPNs might not be needed. Community name: " + obj.name + "\n")
				has2GW = True	
			else:
				has2GW = False
			#Main loop	
			if len(obj.gateways) >1:
				#Creating 1 crypto profile per community
				set_ikecrypto = "set network ike crypto-profiles ike-crypto-profiles " + obj.name + " "
				set_ipseccrypto = "set network ike crypto-profiles ipsec-crypto-profiles " + obj.name + " "
				#IKE profiles
				set_commands.write(set_ikecrypto + "dh-group " + dictionary[obj.dh_grp[0]] + "\n")
				set_commands.write(set_ikecrypto + "encryption " + dictionary[obj.attributes[0]] + "\n")
				set_commands.write(set_ikecrypto + "hash " + dictionary[obj.attributes[1]] + "\n")
				set_commands.write(set_ikecrypto + "lifetime minutes " + obj.attributes[2] + "\n")
				#IPSEC profiles
				set_commands.write(set_ipseccrypto + "esp encryption " + dictionary[obj.attributes[5]] + "\n")
				set_commands.write(set_ipseccrypto + "esp authentication " + dictionary[obj.attributes[6]] + "\n")
				set_commands.write(set_ipseccrypto + "lifetime seconds " + obj.attributes[8] + "\n")
				if obj.attributes[9] == 'true':
					set_commands.write(set_ipseccrypto + "dh-group " + dictionary[obj.dh_grp[1]] + "\n")
				else:
					set_commands.write(set_ipseccrypto + "dh-group no-pfs\n")
				Gateways
				for gateway in obj.gateways:
					printGateways (obj.name, has2GW, LGateway, gateway)
					#print(gwNumber)
					
					
		#print (obj.name , obj.dh_grp, obj.attributes, obj.gateways)
	f.close()
	
	#Lines to look for to get the VPN parameters when the parameter is in the same line
	#VPN_search = [':ike_p1_enc_alg',':ike_p1_hash_alg',':ike_p1_rekey_time', ':ike_p1_use_aggressive (', ':ike_p1_use_shared_secret (', ':ike_p2_enc_alg', ':ike_p2_hash_alg', ':ike_p2_use_rekey_kbytes', ':ike_p2_rekey_time', ':ike_p2_use_pfs', ':tunnel_granularity']
	#Looking for parameters outside the same text line
	#DHG_search = [':ike_p1_dh_grp',':ike_p2_pfs_dh_grp'] 	
	
def printGateways (community, has2GW, localgName, gName):
	set_gateways= open('set_gateways.txt', 'a')	#File to store the set commands for the vpn gateways
	if localgName != gName:
		lgateway = returnGateway(localgName)
		rgateway = returnGateway(gName)
		#print (localgName)
		#print (gName)
		if ((lgateway is None) or (rgateway is None)):
			f = open('warnings.txt', 'w')
			if lgateway is None:
				f.write ("Warning: Gateway without IP address: " + localgName + "\n")
			if rgateway is None:
				f.write ("Warning: Gateway without IP address: " + gName + "\n")
			f.close()
		else:
			set_gateways.write ("set network ike gateway "+gName+ " protocol ikev1 ike-crypto-profile " + community + "\n")	
			set_gateways.write ("set network ike gateway "+gName+" protocol ikev1 exchange-mode main\n")
			set_gateways.write ("set network ike gateway "+gName+ " local-address ip "+ lgateway[0] + "/" +Ext_IF_Netmask +"\n")
			set_gateways.write ("set network ike gateway "+gName+ " local-address interface "+ Ext_IF +"\n")
			set_gateways.write ("set network ike gateway "+gName+ " peer-address ip "+ rgateway[0] + "\n")
			set_gateways.write ("set network tunnel ipsec "+gName+ " auto-key ike-gateway "+ gName + "\n")
			set_gateways.write ("set network tunnel ipsec "+gName+ " auto-key ipsec-crypto-profile "+ community + "\n")
			#print(lgateway[1])
			#print(rgateway[1])
			#print(findProxy(lgateway[1]))
			#print(findProxy(rgateway[1]))
			x=0
			if (lgateway[1] != "0" and rgateway[1] != "0"):
				for localproxy in findProxy(lgateway[1]):
					for remoteproxy in findProxy(rgateway[1]):
						set_gateways.write ("set network tunnel ipsec "+gName+ " auto-key proxy-id proxy_" + str(x) + " protocol any\n")
						set_gateways.write ("set network tunnel ipsec "+gName+ " auto-key proxy-id proxy_" + str(x) + " local " + localproxy + "\n")
						set_gateways.write ("set network tunnel ipsec "+gName+ " auto-key proxy-id proxy_" + str(x) + " remote " + remoteproxy + "\n")
						x+=1
			elif rgateway[1] == 0:
				for localproxy in findProxy(lgateway[1]):
					set_gateways.write ("set network tunnel ipsec "+gName+ " auto-key proxy-id proxy_" + str(x) + " protocol any\n")
					set_gateways.write ("set network tunnel ipsec "+gName+ " auto-key proxy-id proxy_" + str(x) + " local " + localproxy + "\n")
					set_gateways.write ("set network tunnel ipsec "+gName+ " auto-key proxy-id proxy_" + str(x) + " remote 0.0.0.0/0\n")
					x+=1
			elif lgateway[1] == 0:
				for remoteproxy in findProxy(rgateway[1]):
					set_gateways.write ("set network tunnel ipsec "+gName+ " auto-key proxy-id proxy_" + str(x) + " protocol any\n")
					set_gateways.write ("set network tunnel ipsec "+gName+ " auto-key proxy-id proxy_" + str(x) + " local 0.0.0.0/0\n")
					set_gateways.write ("set network tunnel ipsec "+gName+ " auto-key proxy-id proxy_" + str(x) + " remote " + remoteproxy + "\n")
					x+=1
			
		
#function that returns an array with the network or IPs that construct the proxy ID
def findProxy(proxy_id_name):
	a = []
	for obj in Proxy_List:
		if obj.name == proxy_id_name:
			if obj.isGroup:
				for name in obj.proxy_id:
					a= a + findProxy(name)
			else:
				a.append(obj.proxy_id)	
	return a	

	
def returnGateway (gName):
	for gateway in Gateway_List:
		if gateway.name == gName:
			if gateway.proxy_id == '':
				return (gateway.ip, "0")
			else:
				return (gateway.ip, gateway.proxy_id)
		
#VPN class
class VPN:
	def __init__(self, name, DHG_List, attributes, gateways ):
		self.name = name
		#Copying current VPN calues into a the VPN lists
		self.dh_grp = list(DHG_List)
		self.gateways = list(gateways)				
		self.attributes = list(attributes)

#Gateway class
class Gateways:
	def __init__(self, name, ip, local, Proxy_ID ):
		self.name = name
		self.ip = ip
		self.local = local
		self.proxy_id = Proxy_ID

#ProxyID class
class ProxyID:
	def __init__(self, name, isSupported, isGroup, proxy_id):	
		self.name = name
		self.isSupported = isSupported
		self.isGroup = isGroup
		if isGroup:
			self.proxy_id = list(proxy_id)
			self.isCompleted = False			 #New network groups are not completed since we haven't gone through the object members.
		else:
			self.proxy_id = proxy_id

######################################################################################
#MAIN#
######################################################################################

#empty old documents if they exist.
open('set_gateways.txt', 'w').close

####Parsing object_5_.c file and extracting VPN information.
ParseVPN()	
ParseGateway()
Object_List = []
for gateway in Gateway_List:
	Object_List.append (gateway.proxy_id)
ParseProxy(Object_List)

#Debugs
if Dvpn:
	for obj in VPN_List:
		print (obj.name , obj.dh_grp, obj.attributes, obj.gateways)
if DGW:
	for obj in Gateway_List:	
		print (obj.name, obj.ip, obj.local, obj.proxy_id)
if Dproxy:
	for obj in Proxy_List:
		print (obj.name, obj.isSupported, obj.isGroup, obj.proxy_id)


####Getting local gateway name
VPNSettings(LocalGateway())


	#Extracting local gateway info
	
	
	#print (obj.name, obj.ip, obj.local, obj.proxy_id)
#for obj in Proxy_List:
#	print (obj.name, obj.isSupported, obj.isGroup, obj.proxy_id)
##for obj in VPN_List:
#	print (obj.name , obj.dh_grp, obj.attributes, obj.gateways)

#Alerts
#Alert if less than 2 gateways are present, those won't be migrated
#Alert if multiple 3+ gateways are detected in a community, the first gateway will be used as local
#If 2 gateways ae auto-detected as local, use the first one.
#NAT inside VPNs
#Autodetect local firewalls and prompt for which one you want to migrate VPNs from.


