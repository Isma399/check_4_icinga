/*	Check_linux_disk 
	Written from :
 	check_cisco .
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

##########################################################################
MakeFile :   gcc `net-snmp-config --cflags` `net-snmp-config --libs` `net-snmp-config --external-libs` check_linux_disk.c -o check_linux_disk
Usage :  ./check_linux_disk -v 2c -c public <HOSTNAME>
Debug :  ./check_linux_disk -v 2c -c public <HOSTNAME> -D ALL

*/

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>

/* Define useful variables */
#define MISSING_OPTIONS "Unknown or missing options.\n"
#define RESULT_OK 0
#define RESULT_WARNING 1
#define RESULT_CRITICAL 2
#define RESULT_UNKNOWN 3
#define MAX_ERROR_MSG 0x1000

/* Global Variables */
char finalstr[2048],retstr[1024];
int exitVal = RESULT_OK, warn = 80, crit = 90;
char mode[20];

/* Function Definitions */
char *checkDISK(struct snmp_session* session);

/*
  Print usage info.
*/
void usage(void) {
	fprintf(stderr, "USAGE: check_linux_disk ");
	snmp_parse_args_usage(stderr);
	fprintf(stderr, " [OID]\n\n");
	snmp_parse_args_descriptions(stderr);
	fprintf(stderr, "Application specific options.\n");
	fprintf(stderr, "  -C APPOPTS\n");
	fprintf(stderr, "\t\t\t  c:  Set the critical threshold.\n");
	fprintf(stderr, "\t\t\t  w:  Set the warning threshold.\n");
}

int add(netsnmp_pdu *pdu, const char *mibnodename, oid * index, size_t indexlen) {
    oid             base[MAX_OID_LEN];
    size_t          base_length = MAX_OID_LEN;

    memset(base, 0, MAX_OID_LEN * sizeof(oid));

    if (!snmp_parse_oid(mibnodename, base, &base_length)) {
        snmp_perror(mibnodename);
        fprintf(stderr, "couldn't find mib node %s, giving up\n",
                mibnodename);
        exit(1);
    }

    if (index && indexlen) {
        memcpy(&(base[base_length]), index, indexlen * sizeof(oid));
        base_length += indexlen;
    }
    DEBUGMSGTL(("add", "created: "));
    DEBUGMSGOID(("add", base, base_length));
    DEBUGMSG(("add", "\n"));
    snmp_add_null_var(pdu, base, base_length);

    return base_length;
}

netsnmp_variable_list * collect(netsnmp_session * ss, netsnmp_pdu *pdu, oid * base, size_t base_length){
    netsnmp_pdu    *response;
    int             running = 1;
    netsnmp_variable_list *saved = NULL, **vlpp = &saved;
    int             status;

    while (running) {
        status = snmp_synch_response(ss, pdu, &response);
        if (status != STAT_SUCCESS || !response) {
            snmp_sess_perror("snmpdf", ss);
            exit(1);
        }
        if (response && snmp_oid_compare(response->variables->name,
                                         SNMP_MIN(base_length,
                                                  response->variables->
                                                  name_length), base,
                                         base_length) != 0)
            running = 0;
        else {
            *vlpp = response->variables;
            (*vlpp)->next_variable = NULL;      
            pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
            snmp_add_null_var(pdu, (*vlpp)->name, (*vlpp)->name_length);
            vlpp = &((*vlpp)->next_variable);
            response->variables = NULL; 
        }
        snmp_free_pdu(response);
    }
    return saved;
}

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

static int compile_regex (regex_t * r){
	const char *  regex_text = ".+hrStorageFixedDisk.+";
	int status = regcomp (r, regex_text, REG_EXTENDED|REG_NEWLINE);
   	if (status != 0) {
		char error_message[MAX_ERROR_MSG];
		regerror (status, r, error_message, MAX_ERROR_MSG);
       	printf ("Regex error compiling '%s': %s\n",
            regex_text, error_message);
       	return 1;
   	}
   	return 0;
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
	

/* Main program */
int main(int argc, char *argv[]) {
	char* output;
	struct snmp_session session;
	char arg;

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
	output = checkDISK(&session);
	printf("%s", output);
	return exitVal;
}


/*
  Check the Disk Usage on Linux Devices.
*/
char *checkDISK(struct snmp_session* session) {
	//struct snmp_session *ss = NULL;
	netsnmp_session  *ss;
    netsnmp_pdu    *pdu;
    netsnmp_pdu    *response;
	oid             base[MAX_OID_LEN];
    size_t          base_length;
	netsnmp_variable_list *saved = NULL, *vlp = saved, *vlp2;
	int status ;
	regex_t r;
	char partstr[1024], perfString[100];
	unsigned long totalDiskUsed=0,totatDisk=0;
	int testVal=RESULT_OK;
	char human_size_used[10];

	/* Open snmp session, print error if one occurs */
	ss = snmp_open(session);
	if (!ss) {
		printf("ERROR - Problem opening session!\n");
		exit(RESULT_CRITICAL);
	}
	pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
	base_length = add(pdu, "HOST-RESOURCES-MIB:hrStorageIndex", NULL, 0);
	memcpy(base, pdu->variables->name, base_length * sizeof(oid));

	vlp = collect(ss, pdu, base, base_length);
	
	while (vlp) {
		size_t          units;
        unsigned long   hssize, hsused;
        char            descr[SPRINT_MAX_LEN];
        char            hstype[1024];
        
        pdu = snmp_pdu_create(SNMP_MSG_GET);

        add(pdu, "HOST-RESOURCES-MIB:hrStorageType", &(vlp->name[base_length]), vlp->name_length - base_length);
        add(pdu, "HOST-RESOURCES-MIB:hrStorageDescr", &(vlp->name[base_length]), vlp->name_length - base_length);
        add(pdu, "HOST-RESOURCES-MIB:hrStorageAllocationUnits", &(vlp->name[base_length]), vlp->name_length - base_length);
        add(pdu, "HOST-RESOURCES-MIB:hrStorageSize", &(vlp->name[base_length]), vlp->name_length - base_length);
        add(pdu, "HOST-RESOURCES-MIB:hrStorageUsed", &(vlp->name[base_length]), vlp->name_length - base_length);
		
		status = snmp_synch_response(ss, pdu, &response);
		if (status == STAT_ERROR) {
			printf("ERROR - Problem while querying device!\n");
			exit(RESULT_CRITICAL);
		}
		else if (status == STAT_TIMEOUT) {
			printf("ERROR - Connection timed out!\n");
			exit(RESULT_CRITICAL);
		}
		else if (response->errstat != SNMP_ERR_NOERROR) {
			switch (response->errstat) {
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

		vlp2 = response->variables;
        
        snprint_objid(hstype, sizeof(hstype), vlp2->val.objid, vlp2->val_len);
        compile_regex(& r);
        int match = regexec(&r, hstype,0, NULL, 0);
        regfree(& r);
        if(match == 0){
                          
            vlp2 = vlp2->next_variable;
            memcpy(descr, vlp2->val.string, vlp2->val_len);
            descr[vlp2->val_len] = '\0';

            vlp2 = vlp2->next_variable;
            units = vlp2->val.integer ? *(vlp2->val.integer) : 0;
               
            vlp2 = vlp2->next_variable;
            hssize = units * ( vlp2->val.integer ? *(vlp2->val.integer) : 0 );
                
            vlp2 = vlp2->next_variable;
            hsused = units * ( vlp2->val.integer ? *(vlp2->val.integer) : 0 );

            totalDiskUsed+=hsused;
            totatDisk+=hssize;
                
            float usedPercent = (float)(hsused * 100)/hssize;
            //human_size_used = readable_fs(totalDiskUsed, human_size_used);
            //human_disk_size = readable_fs(totatDisk, human_disk_size);
            if (usedPercent > crit) {
                testVal = RESULT_CRITICAL;
                sprintf(partstr, "%s %s(%.1f%%); ", descr, readable_fs(totalDiskUsed, human_size_used), usedPercent);
            }
            else if (usedPercent > warn) {
                testVal = RESULT_WARNING;
                sprintf(partstr, "%s %s(%.1f%%); ", descr, readable_fs(totalDiskUsed, human_size_used), usedPercent);
            }
            else {
                testVal = RESULT_OK;
                sprintf(partstr, "%s %s(%.1f%%); ", descr, readable_fs(totalDiskUsed, human_size_used), usedPercent);
			}
			strcat(retstr,partstr);
		}
		vlp = vlp->next_variable;
		if (testVal == RESULT_CRITICAL){
			exitVal = testVal;
		}
		else if (testVal == RESULT_WARNING){
			exitVal = testVal;
		}
        snmp_free_pdu(response);
    }
	if (exitVal == RESULT_CRITICAL){
		sprintf(finalstr,"CRITICAL - %s", retstr );
	}
	else if (exitVal == RESULT_WARNING){
		sprintf(finalstr,"WARNING - %s", retstr );
	}
	else {
		sprintf(finalstr,"OK - %s", retstr );
	}
	sprintf(perfString," |  totalDiskUsed=%luB totatDisk=%luB\n", totalDiskUsed, totatDisk);
	strcat(finalstr, perfString);
	snmp_close(ss);
	return finalstr;
}

