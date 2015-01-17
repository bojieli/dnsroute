#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

static pcap_t *capture_init(char *dev)
{
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "udp port 53";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return NULL;
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return NULL;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return NULL;
	}
	return handle;
}

#define MAX_DOMAIN_LEN 256
struct domain {
	char name[MAX_DOMAIN_LEN];
	struct domain* next;
};

struct domain *read_domain_list(FILE *fp)
{
	struct domain *list = malloc(sizeof(struct domain));
	struct domain *last = list;
	while (fgets(last->name, MAX_DOMAIN_LEN - 1, fp) != NULL) {
		if (last->name[0] == '#') // comment
			continue;
		char *s = last->name + strlen(last->name) - 1;
		while (*s == '\n' || *s == ' ' || *s == '\r' || *s == '\t') {
			*s-- = '\0';
		}
		last->next = malloc(sizeof(struct domain));
		last = last->next;
	}
	last->next = NULL;
	return list;
}

static char* match_domain_list(struct domain *list, char *haystack)
{
	while (list->next) {
		if (strcasestr(haystack, list->name)) {
			return list->name;
		}
		list = list->next;
	}
	return NULL;
}

#define IP_HEADER_SIZE 20
#define IS_UDP_PACKET(p) ((p)[9] == 0x11)
#define UDP_HEADER_SIZE 8
#define DEST_PORT(p) ((p)[IP_HEADER_SIZE + 2] * 256 + (p)[IP_HEADER_SIZE + 3])
#define SRC_PORT(p) ((p)[IP_HEADER_SIZE] * 256 + (p)[IP_HEADER_SIZE + 1])
#define IS_DNS_RESPONSE(p) (IS_UDP_PACKET(p) && SRC_PORT(p) == 53)
#define DNS_QUERY_OFFSET 12

#define SMALLINT(p) ((*(p) << 8) + *((p) + 1))
#define INT32(p) ((*(p) << 24) + (*((p)+1) << 16) + (*((p)+2) << 8) + *((p)+3))

// return the dns name, caller should free
static char *get_dns_name(int size, unsigned char *pkt)
{
	int len = 0;
	char *name = NULL;
	unsigned char *query = pkt + DNS_QUERY_OFFSET;
	while (query < pkt + size && *query != 0) {
		int newlen = len + *query + 1;
		name = realloc(name, newlen);
		if (len > 0)
			name[len-1] = '.';
		memcpy(name+len, query+1, *query);
		name[newlen-1] = '\0';
		len = newlen;

		query += (*query + 1);
	}
	return (char *)name;
}

static int capture_dns_packet(pcap_t *handle, unsigned char** buf)
{
	while (1) {
		struct pcap_pkthdr header;
		const unsigned char *packet = pcap_next(handle, &header);
		if (packet == NULL)
			continue;
		int size = header.len;
		if (size > IP_HEADER_SIZE + UDP_HEADER_SIZE + DNS_QUERY_OFFSET && IS_DNS_RESPONSE(packet)) {
			*buf = (unsigned char *)packet;
			return size;
		}
	}
	return 0;
}

struct action {
	unsigned int routing_table;
	in_addr_t gateway_ip;

	// for logging
	char *matched_pattern;
	char *domain_name;
};

static void do_action(in_addr_t target_ip, struct action* info)
{
	if (fork() == 0) {
		char dip[20], gw[20], table_name[10];
		struct in_addr _target_ip = {.s_addr = target_ip};
		struct in_addr _gateway_ip = {.s_addr = info->gateway_ip};
		sprintf(dip, "%s/32", inet_ntoa(_target_ip));
		strcpy(gw, inet_ntoa(_gateway_ip));
		sprintf(table_name, "%d", info->routing_table);
		execlp("ip",
			"ip", "route", "replace", dip, "via", gw, "table", table_name,
			(char *)NULL);
	}
}

static void do_for_each_ip(unsigned char* pkt, int size, struct action* info)
{
	int question_num = SMALLINT(pkt + 4);
	int answer_num = SMALLINT(pkt + 6);
	unsigned char *query = pkt + DNS_QUERY_OFFSET;
	while (question_num-- > 0) {
		while (1) {
			unsigned int record_len = *query;
			query += (record_len + 1);
			if (record_len == 0)
				break;
			if (query >= pkt + size)
				return;
		}
		if (SMALLINT(query) != 1) // type A
			return;
		query += 2;
		if (SMALLINT(query) != 1) // type INADDR
			return;
		query += 2;
	}
	while (answer_num-- > 0) {
		int ttl = INT32(query + 6);
		int data_len = SMALLINT(query + 10);
		if (query + 12 + data_len > pkt + size)
			return;
		if (SMALLINT(query + 2) == 1) { // type A
			if (data_len != sizeof(in_addr_t)) {
				fprintf(stderr, "[warning] A record length: %d, not 4\n", data_len);
				return;
			}
			struct in_addr ip;
			memcpy(&ip.s_addr, query + 12, sizeof(in_addr_t));
			printf("IP %s TTL %d for domain %s matching %s\n", inet_ntoa(ip), ttl, info->domain_name, info->matched_pattern);
			do_action(ip.s_addr, info);
		}
		query += 12 + data_len;
	}
}

int main(int argc, char** argv)
{
	if (argc < 5) {
		fprintf(stderr, "Usage: %s <capture-device-name> <domain-name-list-file> <routing-table-id> <gateway-ip>\n", argv[0]);
		return 1;
	}

	char *capture_dev = argv[1];

	FILE *domain_list_fp;
	if ((domain_list_fp = fopen(argv[2], "r")) < 0) {
		fprintf(stderr, "Could not open domain name list file %s\n", argv[2]);
		return 2;
	}

	struct action info;
	info.routing_table = atoi(argv[3]);
	info.gateway_ip = inet_addr(argv[4]);

	struct domain *domain_list;
	domain_list = read_domain_list(domain_list_fp);
	if (!domain_list || domain_list->next == NULL) {
		fprintf(stderr, "domain name list file %s is empty\n", argv[2]);
		return 2;
	}

	pcap_t *pcap_handle;
	if ((pcap_handle = capture_init(capture_dev)) == NULL) {
		fprintf(stderr, "capture device %s failed\n", capture_dev);
		return 3;
	}

	while (1) {
		unsigned char *buf;
		int size = capture_dns_packet(pcap_handle, &buf);
		if (size == 0) {
			fprintf(stderr, "packet sniff error!\n");
			return 4;
		}

		unsigned char *pkt = buf + IP_HEADER_SIZE + UDP_HEADER_SIZE;
		char *dns_name = get_dns_name(size, pkt);
		if (!dns_name)
			continue;

#ifdef DEBUG
		printf("DNS query: %s\n", dns_name);
#endif

		char *matched;
		if ((matched = match_domain_list(domain_list, dns_name))) {
#ifdef DEBUG
			printf("Domain %s match pattern %s\n", dns_name, matched);
#endif
			info.matched_pattern = matched;
			info.domain_name = dns_name;
			do_for_each_ip(pkt, size, &info);
		}
		free(dns_name);
	}
}

