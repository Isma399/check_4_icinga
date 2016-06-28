/*
 * Check Linux Inode
 *
 */
/***********************************************************************
	Copyright 1988, 1989, 1991, 1992 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

########################################################################

MakeFile = gcc `net-snmp-config --cflags` `net-snmp-config --libs` `net-snmp-config --external-libs` check_linux_inode.c -o check_linux_inode
Usage :  ./check_linux_inode -v 2c -c public
Debug :  ./check_linux_inode -v 2c -c public -D ALL
******************************************************************/
#include <net-snmp/net-snmp-config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <ctype.h>
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <regex.h>

#define MAX_ERROR_MSG 0x1000
#define RESULT_OK 0
#define RESULT_WARNING 1
#define RESULT_CRITICAL 2
#define RESULT_UNKNOWN 3

/* Global Variables */

int exitVal = RESULT_OK, warn = 80, crit = 90;
int  failures = 0;
char finalstr[2048],retstr[1024],mode[20];

/* Function Definitions */
char *checkINODE(struct snmp_session* session);

void usage(void)
{
    fprintf(stderr, "Usage: snmpdf [-Cu] ");
    snmp_parse_args_usage(stderr);
    fprintf(stderr, "\n\n");
    snmp_parse_args_descriptions(stderr);
    fprintf(stderr, "\nsnmpdf options:\n");
    fprintf(stderr,
            "\t-Cu\tUse UCD-SNMP dskTable to do the calculations.\n");
    fprintf(stderr,
            "\t\t[Normally the HOST-RESOURCES-MIB is consulted first.]\n");
}

int ucd_mib = 0;

static void optProc(int argc, char *const *argv, int opt)
{
    switch (opt) {
    case 'C':
        while (*optarg) {
            switch (*optarg++) {
            case 'u':
                ucd_mib = 1;
                break;
            default:
                fprintf(stderr,
                        "Unknown flag passed to -C: %c\n", optarg[-1]);
                exit(1);
            }
        }
    }
}
struct hrStorageTable {
    u_long          hrStorageIndex;
    oid            *hrStorageType;
    char           *hrStorageDescr;
    u_long          hrStorageAllocationUnits;
    u_long          hrStorageSize;
    u_long          hrStorageUsed;
};

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
    output = checkINODE(&session);
    printf("%s", output);
    return exitVal;
}
    

char *checkINODE(struct snmp_session* session) {
    //struct snmp_session *ss = NULL;
    netsnmp_session  *ss;
    netsnmp_pdu    *pdu;
    netsnmp_pdu    *response;
    oid             base[MAX_OID_LEN];
    size_t          base_length;
    netsnmp_variable_list *saved = NULL, *vlp = saved, *vlp2;
    int status ;
    char partstr[1024];
    int usedPercent;
    int testVal=RESULT_OK;
    

    /* Open snmp session, print error if one occurs */
    ss = snmp_open(session);
    if (!ss) {
        printf("ERROR - Problem opening session!\n");
        exit(RESULT_CRITICAL);
    }
    pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
    base_length = add(pdu, "UCD-SNMP-MIB:dskIndex", NULL, 0);
    memcpy(base, pdu->variables->name, base_length * sizeof(oid));

    vlp = collect(ss, pdu, base, base_length);
    
    while (vlp) {
        char            descr[SPRINT_MAX_LEN];
        
        pdu = snmp_pdu_create(SNMP_MSG_GET);

        add(pdu, "UCD-SNMP-MIB:dskPath", &(vlp->name[base_length]), vlp->name_length - base_length);
        add(pdu, "UCD-SNMP-MIB:dskPercentNode", &(vlp->name[base_length]), vlp->name_length - base_length);
        
        
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
        memcpy(descr, vlp2->val.string, vlp2->val_len);
        descr[vlp2->val_len] = '\0';

        vlp2 = vlp2->next_variable;
        usedPercent = *(vlp2->val.integer);
        
            if (usedPercent > crit) {
                testVal = RESULT_CRITICAL;
                sprintf(partstr, "%s(%i%%); ", descr, usedPercent);
            }
            else if (usedPercent > warn) {
                testVal = RESULT_WARNING;
                sprintf(partstr, "%s(%i%%); ", descr, usedPercent);
            }
            else {
                testVal = RESULT_OK;
                sprintf(partstr, "%s(%i%%); ", descr, usedPercent);
            }
            strcat(retstr,partstr);

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
    snmp_close(ss);
    return finalstr;
}                     /* end main() */
