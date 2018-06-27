#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfvar.h>

#include "errorlog.h"

#define FAILURE -1
#define SUCCESS 1

#define UNIFIED2_EVENT               1
#define UNIFIED2_PACKET              2
#define UNIFIED2_IDS_EVENT           7
#define UNIFIED2_IDS_EVENT_IPV6      72
#define UNIFIED2_IDS_EVENT_MPLS      99
#define UNIFIED2_IDS_EVENT_IPV6_MPLS 100
#define UNIFIED2_IDS_EVENT_VLAN      104
#define UNIFIED2_IDS_EVENT_IPV6_VLAN 105
#define UNIFIED2_EXTRA_DATA          110

#define TO_IP(x) x >> 24, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff

/* UNIFIED2_IDS_EVENT_VLAN = type 104
 * comes from SFDC to EStreamer archive 
 * in serialized form with the extended header
 */
struct Unified2IDSEvent
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  impact_flag;//overloads packet_action
    uint8_t  impact;
    uint8_t  blocked;
    uint32_t mpls_label;
    uint16_t vlanId;
    uint16_t pad2;//Policy ID
#if defined(FEAT_OPEN_APPID)
    char     app_name[MAX_EVENT_APPNAME_LEN];
#endif /* defined(FEAT_OPEN_APPID) */
};

struct record {
    uint32_t type;
    uint32_t len;
    uint8_t  *data;    
};

int debug;
int get_record(int, struct record *);
int table_add_addr(const char * tbl, uint32_t *ip);

int main(int argc, char *argv[])
{
	struct rlimit		rlim_ptr;
	struct record 		rec;
	struct Unified2IDSEvent *ids_ev;
	char 			logfile[] = "/var/snort/log/merged.log";
	int			i, log;

	debug = 0;

	log_open(argv[0], LOG_PID, LOG_DAEMON);

        if (getrlimit(RLIMIT_NOFILE, &rlim_ptr) < 0)
            printf("rlimit failed %s", strerror(errno));

        for (i = 3; i <= (int)rlim_ptr.rlim_cur; i++)
            close(i);

        if (debug == 0) 
            if (daemon(0, 0) < 0)
                log_die("Failed to daemonize", errno);


	if (pledge("stdio pf rpath", NULL) == -1) {
	    printf("pledge error: %s\n", strerror(errno));
	    exit(-1);
	}

	memset(&rec, 0, sizeof(rec));

	if ((log = open(logfile, O_RDONLY)) < 0)
	    log_syserr("open() error: %s\n", strerror(errno));

	if (lseek(log, 0, SEEK_END) == -1)
	    log_syserr("lseek() error: ");

	while (1) {
	    if (get_record(log, &rec) != SUCCESS) {
		log_msg("get_record() failure\n");
		sleep(3);
	    }

/*	    printf("Type: %d Length %d\n", rec.type, rec.len); */

	    if (rec.type == UNIFIED2_IDS_EVENT_VLAN) {
		ids_ev = (struct Unified2IDSEvent *)rec.data;
		if (ntohl(ids_ev->signature_id) == 1)
		    sigid_1(&rec);
	    }
	    free(rec.data);
	}
}

int sigid_1(struct record *r)
{
	uint32_t ip;
	int i;

	ip = ntohl( ((struct Unified2IDSEvent *)r->data)->ip_source );
	log_msg("SNID_1: ip blocK: %u.%u.%u.%u\n", TO_IP(ip));

	if (!debug) {
	    if (table_add_addr("smtp_blacklist", &((struct Unified2IDSEvent *)r->data)->ip_source ))
		printf("Error adding addr to table\n");
	}	
}

int table_add_addr(const char * tbl, uint32_t *ip)
{
	struct pfioc_table	pfioc_t;
	struct pfr_addr		pfaddr;
	int			fd;
	int			r;
	int			flags, opts = 0;
	int			nadd;
	
	bzero(&pfaddr, sizeof(struct pfr_addr));
	bzero(&pfioc_t, sizeof(struct pfioc_table));
	bzero(&pfioc_t.pfrio_table, sizeof(struct pfr_table));

	strlcpy(pfioc_t.pfrio_table.pfrt_name, "testable", PF_TABLE_NAME_SIZE);

	pfaddr.pfra_af = AF_INET;
	pfaddr.pfra_not = 0;
	pfaddr.pfra_net = 32;

	pfaddr.pfra_u._pfra_ip4addr.s_addr = *ip;
	pfioc_t.pfrio_size = 1;
	pfioc_t.pfrio_esize = sizeof(pfaddr);
	pfioc_t.pfrio_buffer = &pfaddr;
	pfioc_t.pfrio_flags = 0;
	
	if ((fd = open("/dev/pf", O_RDWR)) < 0) {
	    printf("open(2) error: %s\n", strerror(errno));
	    exit(-1);
	}

	if(ioctl(fd, DIOCRADDADDRS, &pfioc_t) == -1) {
	    printf("ioctl(2) error: %s\n", strerror(errno));
	    exit(-1);
	}
	close(fd);
}

int get_record(int lfd, struct record *r) 
{
	size_t hbytes;
	size_t dbytes;
	size_t start, off;

	/* read type and length */ 	

	if ((start = lseek(lfd, 0, SEEK_CUR)) == -1)
	    log_syserr("lseek() error: ");

	for(;;) {

	    off = 0;
	    hbytes = pread(lfd, r, sizeof(uint32_t) * 2, start);
	    if (hbytes == 0) {
		sleep(3);
		continue;
	    } else if (hbytes == -1) {
		log_msg("pread() error: ");
		sleep(3);
		continue;
	    }

	    off += hbytes;
	    r->type = ntohl(r->type);
	    r->len = ntohl(r->len);

	    if ((r->data = malloc(r->len)) == NULL) {
		log_msg("malloc() error %s %d\n", strerror(errno), r->len);
		sleep(3);
		continue;
	    }

	    dbytes = pread(lfd, r->data, r->len, off);

	    if (dbytes <= 0) {
		if (dbytes == 0) {
		    sleep(3);
		} else if (dbytes == -1) {
		    log_msg("pread() error: ");
		    sleep(3);
		}
		free(r->data);
		continue;		
	    } else {
		off += dbytes;
		if (dbytes < r->len) {			/* SHORT READ */
		    log_msg("short pread()");
		    free(r->data);
		    continue;
		}
		/* FALL THROUGH */
	    }
	    break;
	}
	if (lseek(lfd, off, SEEK_CUR) == -1)
	    log_syserr("lseek() error: ");

/*	if (r->type != UNIFIED2_PACKET || nbytes < ntohl(((Serial_Unified2Packet*)r->data)->packet_len))
*            return FAILURE;
*/
	return SUCCESS;
}

