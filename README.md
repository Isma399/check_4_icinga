# check_4_icinga

SNMP checks for linux devices, written in C, made for Icinga.

Code was orginally based off check_cisco.c by Jason Harris
 * https://exchange.nagios.org/directory/Plugins/Network-Connections,-Stats-and-Bandwidth/Check-Cisco-Devices/details
 * https://sourceforge.net/u/micha137/net-snmp/ci/master/tree/apps/snmpdf.c


### Usage


    ./check_linux_xxx -v 2c -c <COMMUNITY> <HOSTNAME>
    
    # Debugging Arguments
    ./check_linux_xxx -v 2c -c <COMMUNITY> <HOSTNAME> -D ALL


### Prerequisites

You will need CMake >= 3.5, and Net-SNMP.

### Installing

to install directly from source

    ./scripts/build.sh
    sudo ./scripts/install.sh



### Deployment

to generate an RPM 

    ./scripts/release-source.sh
    ./scripts/release-binary_rpm.sh

