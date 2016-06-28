/*	Check_linux_load
	Written from : 
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

##############################################################################
MakeFile :   gcc `net-snmp-config --cflags` `net-snmp-config --libs` `net-snmp-config --external-libs` check_linux_disk.c -o check_linux_disk
Usage :  ./check_linux_disk -v 2c -c public <HOSTNAME>
Debug :  ./check_linux_disk -v 2c -c public <HOSTNAME> -D ALL
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
char retstr[120];
int exitVal = RESULT_UNKNOWN, warn = 80, crit = 90;
char mode[20];

/* Function Definitions */
char *checkCPU(struct snmp_session* session);

/*
  Print usage info.
*/
void usage(void) {
	fprintf(stderr, "USAGE: check_cisco ");
	snmp_parse_args_usage(stderr);
	fprintf(stderr, " [OID]\n\n");
	snmp_parse_args_descriptions(stderr);
	fprintf(stderr, "Application specific options.\n");
	fprintf(stderr, "  -C APPOPTS\n");
	fprintf(stderr, "\t\t\t  c:  Set the critical threshold.\n");
	fprintf(stderr, "\t\t\t  m:  Set the operation mode [cpu|failover|memory|sessions|temp|3750temp]\n");
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
		

	output = checkCPU(&session);
	

	printf("%s", output);
	return exitVal;
}



/*
  Check the CPU load percentage on Linux Devices.
*/
char *checkCPU(struct snmp_session* session) {
	struct snmp_session *s_handle = NULL;
	struct snmp_pdu *pdu = NULL;
	struct snmp_pdu *reply = NULL;
	struct variable_list *vars;
	int status ;
	//char CPU;
	
	oid mib_CPU[] = { 1, 3, 6, 1, 4, 1, 2021, 10, 1, 3, 2};
	
	/* Open snmp session, print error if one occurs */
	s_handle = snmp_open( session );
	if (!s_handle) {
		printf("ERROR - Problem opening session!\n");
		exit(RESULT_CRITICAL);
	}
	
	/* Build PDU and add desired OID's */
	pdu = snmp_pdu_create(SNMP_MSG_GET);

	snmp_add_null_var(pdu, mib_CPU, OID_LENGTH(mib_CPU));
	
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
		
	vars = reply->variables;
	if ((vars == NULL) || (vars->type == ASN_NULL)) {
		printf("ERROR - No data recieved from device\n");
		exit(RESULT_UNKNOWN);
	}
	
    for(vars = reply->variables; vars; vars = vars->next_variable) {
    	char *sp = (char *)malloc(1 + vars->val_len);
		memcpy(sp, vars->val.string, vars->val_len);
		sp[vars->val_len] = '\0';
        float CPU;
     	CPU = atof(sp);
    	free(sp);
        if (CPU > crit) {
			exitVal = RESULT_CRITICAL;
			sprintf(retstr, "CRITICAL - CPU Load: %.2f%% | load=%.2f%%\n", CPU, CPU);
		}
	
		else if (CPU > warn) {
			exitVal = RESULT_WARNING;
			sprintf(retstr, "WARNING - CPU Load: %.2f%% | load=%.2f%%\n", CPU, CPU);
		}
		else {
			exitVal = RESULT_OK;
			sprintf(retstr, "OK - CPU Load: %.2f%% | load=%.2f%%\n", CPU , CPU);
		}
	}
	
	snmp_free_pdu(reply);
	snmp_close(s_handle);
	return retstr;
}
