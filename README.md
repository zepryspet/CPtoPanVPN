# CPtoPanVPN
Script to generate set commands from a checkpoint VPN to a palo alto VPN

This script will generate the adequate set commands for a palo alto firewall based on the VPNS located at the "objects_5_0.C" file in a checkpoint management server.
___
Requirements:
1. Python 3
___
steps:
1. Export the objects file file from checkpoint management server. It's usually located in the followaing location.
> cd $FWDIR/conf/objects_5_0.C

2. Dowload the script into the same folder as the object.
> https://github.com/zepryspet/CPtoPanVPN/blob/master/cp-vpns.py

3. Modify the external the following variables in the script to fit your external interface in the palo alto firewall.
>#Variables to modify#

>Ext_IF = 'ethernet1/1' #External interface to setup the VPNs, 

>Ext_IF_Netmask = '24'	#External interface IP address netmask to setup the VPNs, 

4. Execute the script Either double click on it or from the cmd.

5. The set commands will be generated within the same folder in the following 2 documents:
> set_crypto.txt
> set_gateways.txt
___
Troubleshooting
1. Excute the script from the CMD to see if any particular statements is breaking the script
2. check the "warnings.txt" file for any error 

___
know limitations:
1. Won't migrate pre-shared keys since those are encrypted in FWAUTH
2. Won't create tunnel interfaces for the VPNs.
3. No ipv6 compability.
