# check_4_icinga
SNMP checks for linux devices, written in C, made for Icinga.

I used this scripts to write the checks :
-check_cisco.c from Jason Harris : https://exchange.nagios.org/directory/Plugins/Network-Connections,-Stats-and-Bandwidth/Check-Cisco-Devices/details
-https://sourceforge.net/u/micha137/net-snmp/ci/master/tree/apps/snmpdf.c



MakeFile :   gcc `net-snmp-config --cflags` `net-snmp-config --libs` `net-snmp-config --external-libs` check_linux_xxx.c -o check_linux_xxx
Usage :  ./check_linux_xxx -v 2c -c <COMMUNITY> <HOSTNAME>
Debug :  ./check_linux_xxx -v 2c -c <COMMUNITY> <HOSTNAME> -D ALL
