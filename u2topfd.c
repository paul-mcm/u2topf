#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <net/if.h>
#include <net/pfvar.h>

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
    uint32_t r_type;
    uint32_t r_len;
    uint8_t  *data;    
};

int get_record(FILE *, struct record *);
int table_add_addr(const char * tbl, uint32_t *ip);

int main(int argc, char *argv[])
{
	struct record rec;
	struct Unified2IDSEvent *ids_ev;
	char logfile[] = "/var/snort/log/merged.log";
/*	char logfile[] = "./merged.log"; */
	FILE *log;
	memset(&rec, 0, sizeof(rec));

	if ((log = fopen(logfile, "r")) < 0) {
	    printf("fopen error: %s\n", strerror(errno));
	    exit(-1);
	}

	fseek(log, 0, SEEK_END);

	while (1) {
	    if (get_record(log, &rec) != SUCCESS) {
		printf("get_record() failure\n");
		sleep(3);
	    }

/*	    printf("Type: %d Length %d Offset %d\n", rec.r_type, rec.r_len, ftell(log)); */

	    if (rec.r_type == UNIFIED2_IDS_EVENT_VLAN) {
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
	printf("%u.%u.%u.%u\n", TO_IP(ip));

	if (table_add_addr("testable", &((struct Unified2IDSEvent *)r->data)->ip_source ))
	    printf("Error adding addr to table\n");
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

int get_record(FILE *fp, struct record *r) 
{
	size_t hbytes;
	size_t dbytes;
     
	/* read type and length */ 

	for(;;) {

	    hbytes = fread(r, 1, sizeof(uint32_t) * 2, fp);
	    if (hbytes == 0 || hbytes != sizeof(uint32_t) * 2) {

		if (ferror(fp)) {
		    printf("ferror(): %s\n", strerror(errno));
		    clearerr(fp);
		}

		if (feof(fp)) {
		    printf("feof() sleeping\n");
		    sleep(3);
		    clearerr(fp);
		    continue;
		}
		printf("seeking1\n");
		sleep(3);
		fseek(fp, -(hbytes), SEEK_CUR);
		continue;
	    }

	    r->r_type = ntohl(r->r_type);
	    r->r_len = ntohl(r->r_len);

	    if ((r->data = malloc(r->r_len)) == NULL) {
		printf("malloc() error %s %d\n", strerror(errno), r->r_len);
		sleep(3);
		fseek(fp, -(hbytes), SEEK_CUR);
		continue;
	    }

	    dbytes = fread(r->data, 1, r->r_len, fp);
	    if (dbytes == 0 || dbytes != r->r_len) {

		if (ferror(fp)) {
		    printf("ferror(): %s\n", strerror(errno));
		    clearerr(fp);
		}

		if (feof(fp)) {
		    printf("feof() sleeping\n");
		    sleep(3);
		    clearerr(fp);
		    continue;
		}
		printf("seeking1\n");
		fseek(fp, -(hbytes + dbytes), SEEK_CUR);
		continue;
	    }

	    break;
	}

/*	if (r->r_type != UNIFIED2_PACKET || nbytes < ntohl(((Serial_Unified2Packet*)r->data)->packet_len))
*            return FAILURE;
*/
	return SUCCESS;
}
