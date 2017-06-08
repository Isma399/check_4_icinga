/*	Check_linux_ram
	written from :
 	Check_cisco checks various snmp statistics related to Cisco devices.
    Copyright (C) 2012  Jason Harris

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

 #############################################################################   
 MakeFile :   gcc `net-snmp-config --cflags` `net-snmp-config --libs` `net-snmp-config --external-libs` check_linux_ram.c -o check_linux_ram
 Usage :  ./check_linux_ram -v 2c -c public <HOSTNAME>
 Debug :  ./check_linux_ram -v 2c -c public <HOSTNAME> -D ALL
*/

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdio.h>
#include <string.h>

/* Define useful variables */
#define MISSING_OPTIONS "Unknown or missing options.\n"
#define RESULT_OK 0
#define RESULT_WARNING 1
#define RESULT_CRITICAL 2
#define RESULT_UNKNOWN 3

/* Global Variables */
char retstr[500];
int exitVal = RESULT_UNKNOWN, warn = 80, crit = 90;
char mode[20];

/* Function Definitions */
char *checkRAM(struct snmp_session* session);

/*
  Print usage info.
*/
void usage(void) {
	fprintf(stderr, "USAGE: check_linux_ram ");
	snmp_parse_args_usage(stderr);
	fprintf(stderr, " [OID]\n\n");
	snmp_parse_args_descriptions(stderr);
	fprintf(stderr, "Application specific options.\n");
	fprintf(stderr, "  -C APPOPTS\n");
	fprintf(stderr, "\t\t\t  c:  Set the critical threshold.\n");
	fprintf(stderr, "\t\t\t  w:  Set the warning threshold.\n");
}

/*
  Process input options.
*/
void optProc(int argc, char *const *argv, int opt) {
	switch (opt) {
		case 'C':
			while (*optarg) {
				switch (*optarg++) {
					case 'c':
						crit = atoi(argv[optind++]);
						break;
					case 'm':
						strcpy(mode, argv[optind++]);
						break;
					case 'w':
						warn = atoi(argv[optind++]);
						break;
				}
			}
	break;
	}
}
char* readable_fs(long unsigned bytes_size, char *human_size) {
    int i = 0;
    const char* units[] = {"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
    while (bytes_size > 1024) {
        bytes_size /= 1024;
        i++;
    }
    sprintf(human_size, "%lu%s", bytes_size, units[i]);
    return human_size;
}

/* Main program 
	Queries various SNMP values on cisco devices.
*/
int main(int argc, char *argv[]) {
	char* output;
	struct snmp_session session;
	char arg;
//	int i;
//	long snmpVer;

	/* Initialize and build snmp session, add version, community, host, etc */
	init_snmp("Linux_checks");
	
	snmp_sess_init( &session );

	switch (arg = snmp_parse_args(argc, argv, &session, "C:", optProc)) {
	case -3:
		exit(1);
	case -2:
		exit(0);
	case -1:
		usage();
		exit(1);
	default:
		break;
	}
	
	/* Check warning/critical test values to verify they are within the appropriate ranges */
	if ((crit > 100) && (strcmp(mode, "sessions"))) {
		printf("Critical threshold should be less than 100!\n");
		usage();
		exit(RESULT_UNKNOWN);
	}
	else if (crit < 0) {
		printf("Critical threshould must be greater than 0!\n");
		usage();
		exit(RESULT_UNKNOWN);
	}
	else if ((warn < 0) && (strcmp(mode, "sessions"))) {
		printf("Warning threshold must be greater than or equal to 0!\n");
		usage();
		exit(RESULT_UNKNOWN);
	}
	else if (warn > crit) {
		printf("Warning threshold must not be greater than critical threshold!\n");
		usage();
		exit(RESULT_UNKNOWN);
	}
		

	output = checkRAM(&session);
	

	printf("%s", output);
	return exitVal;
}



/*
  Check the RAM load percentage on Linux Devices.
*/
char *checkRAM(struct snmp_session* session) {
	struct snmp_session *s_handle = NULL;
	struct snmp_pdu *pdu = NULL;
	struct snmp_pdu *reply = NULL;
	struct variable_list *vars;
	int status ;
	double total,buffers,cache,totalSwap,availSwap,available,used,unused,swap;
	float usedPercent;
	char	human_size[10];
	
	oid mib_total[] = { 1, 3, 6, 1, 4, 1, 2021, 4, 5, 0 };
	oid mib_buffers[] = { 1, 3, 6, 1, 4, 1, 2021, 4, 14, 0};
    oid mib_cache[] = { 1, 3, 6, 1, 4, 1, 2021, 4, 15, 0};
    oid mib_totalSwap[] = { 1,3, 6, 1, 4, 1, 2021, 4, 3, 0};
    oid mib_availSwap[] = { 1, 3, 6, 1, 4, 1, 2021, 4, 4, 0};
    oid mib_available[] = { 1, 3, 6, 1, 4, 1, 2021, 4, 6, 0};
	
	/* Open snmp session, print error if one occurs */
	s_handle = snmp_open( session );
	if (!s_handle) {
		printf("ERROR - Problem opening session!\n");
		exit(RESULT_CRITICAL);
	}
	
	/* Build PDU and add desired OID's */
	pdu = snmp_pdu_create(SNMP_MSG_GET);

	snmp_add_null_var(pdu, mib_total, OID_LENGTH(mib_total));
	snmp_add_null_var(pdu, mib_buffers, OID_LENGTH(mib_buffers));
	snmp_add_null_var(pdu, mib_cache, OID_LENGTH(mib_cache));
	snmp_add_null_var(pdu, mib_totalSwap, OID_LENGTH(mib_totalSwap));
	snmp_add_null_var(pdu, mib_availSwap, OID_LENGTH(mib_availSwap));
	snmp_add_null_var(pdu, mib_available, OID_LENGTH(mib_available));
		
			
	/* Check if snmp synchs correctly, if not exit the program */
	status = snmp_synch_response(s_handle, pdu, &reply);
	if (status == STAT_ERROR) {
		printf("ERROR - Problem while querying device!\n");
		exit(RESULT_CRITICAL);
	}
	else if (status == STAT_TIMEOUT) {
		printf("ERROR - Connection timed out!\n");
		exit(RESULT_CRITICAL);
	}
	else if (reply->errstat != SNMP_ERR_NOERROR) {
		switch (reply->errstat) {
			case SNMP_ERR_NOSUCHNAME:
				printf("ERROR - Device does not support that feature!\n");
				break;
			case SNMP_ERR_TOOBIG:
				printf("ERROR - Result generated too much data!\n");
				break;
			case SNMP_ERR_READONLY:
				printf("ERROR - Value is read only!\n");
				break;
			case SNMP_ERR_BADVALUE:
			case SNMP_ERR_GENERR:
			case SNMP_ERR_NOACCESS:
			case SNMP_ERR_WRONGTYPE:
			case SNMP_ERR_WRONGLENGTH:
			case SNMP_ERR_WRONGENCODING:
			case SNMP_ERR_WRONGVALUE:
			case SNMP_ERR_NOCREATION:
			case SNMP_ERR_INCONSISTENTVALUE:
			case SNMP_ERR_RESOURCEUNAVAILABLE:
			case SNMP_ERR_COMMITFAILED:
			case SNMP_ERR_UNDOFAILED:
			case SNMP_ERR_AUTHORIZATIONERROR:
			case SNMP_ERR_NOTWRITABLE:
			case SNMP_ERR_INCONSISTENTNAME:
			default:
				printf("ERROR - Unknown error!\n");
		}
		exit(RESULT_CRITICAL);
	}
		
	
  /* Read out data returned from device, print error if data is NULL */
	
	
	
	vars = reply->variables;
	if ((vars == NULL) || (vars->type == ASN_NULL)) {
		printf("ERROR - No data recieved from device\n");
		exit(RESULT_UNKNOWN);
	}
	total = (int)1024*(*vars->val.integer);

	vars = vars->next_variable;
	if ((vars == NULL) || (vars->type == ASN_NULL)) {
		printf("ERROR - No data recieved from device\n");
		exit(RESULT_UNKNOWN);
	}
	buffers = (int)1024*(*vars->val.integer);
	
	vars = vars->next_variable;
	if ((vars == NULL) || (vars->type == ASN_NULL)) {
		printf("ERROR - No data recieved from device\n");
		exit(RESULT_UNKNOWN);
	}
	cache = (int)1024*(*vars->val.integer);
	
	vars = vars->next_variable;
	if ((vars == NULL) || (vars->type == ASN_NULL)) {
		printf("ERROR - No data recieved from device\n");
		exit(RESULT_UNKNOWN);
	}
	totalSwap = (int)1024*(*vars->val.integer);
	
	vars = vars->next_variable;
	if ((vars == NULL) || (vars->type == ASN_NULL)) {
		printf("ERROR - No data recieved from device\n");
		exit(RESULT_UNKNOWN);
	}
	availSwap = (int)1024*(*vars->val.integer);

	vars = vars->next_variable;
	if ((vars == NULL) || (vars->type == ASN_NULL)) {
		printf("ERROR - No data recieved from device\n");
		exit(RESULT_UNKNOWN);
	}
	available = (int)1024*(*vars->val.integer);
	
	/*Calcul des valeurs */
	used = (total-(buffers+cache+available));
    swap = (totalSwap-availSwap);
    usedPercent = (float)(total - buffers - cache -available)*100/total;
    unused = total - used;
    
	if (usedPercent > crit) {
		exitVal = RESULT_CRITICAL;
		sprintf(retstr, "CRITICAL - %.2f%% used on %s  | usedReal=%.f buffers=%.f cache=%.f unusedReal=%.f usedSwap=%.f total=%.f \n", usedPercent, readable_fs(total, human_size) , used, buffers, cache, unused, swap, total);
	}
	else if (usedPercent > warn) {
		exitVal = RESULT_WARNING;
		sprintf(retstr, "WARNING - %.2f%% used on %s  | usedReal=%.f buffers=%.f cache=%.f unusedReal=%.f usedSwap=%.f total=%.f \n", usedPercent, readable_fs(total, human_size), used, buffers, cache, unused, swap, total);
	}
	else {
		exitVal = RESULT_OK;
		sprintf(retstr, "OK - %.2f%% used on %s  | usedReal=%.f buffers=%.f cache=%.f unusedReal=%.f usedSwap=%.f total=%.f \n", usedPercent, readable_fs(total, human_size), used, buffers, cache, unused, swap, total);
	}
	
	snmp_free_pdu(reply);
	snmp_close(s_handle);
	return retstr;
}
