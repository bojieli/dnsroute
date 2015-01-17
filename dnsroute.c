#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

int tun_alloc(char *dev)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
		return fd;

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, &ifr)) < 0) {
		close(fd);
		return err;
	}
	return fd;
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

static char* match_domain_list(struct domain *list, char *needle)
{
	while (list->next) {
		if (strcasestr(list->name, needle)) {
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
#define SMALLINT(p) (*(p) * 256 + *((p) + 1))

#define PACKET_BUF_SIZE 4096

// return the dns name, caller should free
static char *get_dns_name(int size, unsigned char *pkt)
{
	int len = 0;
	char *name = NULL;
	unsigned char *query = pkt + DNS_QUERY_OFFSET;
	while (query < pkt + size && *query != 0) {
		int newlen = len + *query + 1;
		name = realloc(name, newlen);
		name[len-1] = '.';
		memcpy(name+len, query+1, *query);
		name[newlen-1] = '\0';

		query += (*query + 1);
	}
	return (char *)name;
}

static int capture_dns_packet(int tun_fd, unsigned char* buf)
{
	while (1) {
		int size = read(tun_fd, buf, PACKET_BUF_SIZE);
		if (size < 0) {
			fprintf(stderr, "[warning] read from tun_fd %d: return %d\n", tun_fd, size);
			continue;
		}
		if (size > IP_HEADER_SIZE + UDP_HEADER_SIZE + DNS_QUERY_OFFSET && IS_DNS_RESPONSE(buf)) {
			return size;
		}
	}
}

struct action {
	unsigned int routing_table;
	in_addr_t gateway_ip;
};

static void do_action(in_addr_t target_ip, struct action* info)
{
	if (fork() == 0) {
		char dip[20] = {0}, gw[20] = {0}, table_name[10] = {0};
		struct in_addr _target_ip = {.s_addr = target_ip};
		struct in_addr _gateway_ip = {.s_addr = info->gateway_ip};
		sprintf(dip, "%s/32", inet_ntoa(_target_ip));
		strcpy(gw, inet_ntoa(_gateway_ip));
		sprintf(table_name, "%d", info->routing_table);
		execlp("ip", "route", "replace", dip, "via", gw, "table", table_name, NULL);
	}
}

static void do_for_each_ip(unsigned char* pkt, int size, struct action* info)
{
	int question_num = SMALLINT(pkt + 4);
	int answer_num = SMALLINT(pkt + 6);
	unsigned char *query = pkt + DNS_QUERY_OFFSET;
	while (question_num-- > 0) {
		while (*query) {
			query += (*query + 1);
			if (query >= pkt + size)
				return;
		}
		query += 4; // type, class
	}
	while (answer_num-- > 0) {
		int data_len = *(query + SMALLINT(query + 8));
		if (query + 10 + data_len > query)
			return;
		if (SMALLINT(pkt + 2) == 1) { // type A
			if (data_len != sizeof(in_addr_t)) {
				fprintf(stderr, "[warning] A record length: %d, not 4\n", data_len);
				return;
			}
			struct in_addr ip;
			memcpy(&ip.s_addr, pkt + 10, sizeof(in_addr_t));
			printf("Found IP %s\n", inet_ntoa(ip));
			do_action(ip.s_addr, info);
		}
	}
}

int main(int argc, char** argv)
{
	char *tun_dev;
	int tun_fd;
	FILE *domain_list_fp;
	struct domain *domain_list;
	struct action info;

	if (argc < 5) {
		fprintf(stderr, "Usage: %s <tun-device-name> <domain-name-list-file> <routing-table-id> <gateway-ip>\n", argv[0]);
		return 1;
	}

	tun_dev = argv[1];
	if ((domain_list_fp = fopen(argv[2], "r")) < 0) {
		fprintf(stderr, "Could not open domain name list file %s\n", argv[2]);
		return 2;
	}
	info.routing_table = atoi(argv[3]);
	info.gateway_ip = inet_addr(argv[4]);

	domain_list = read_domain_list(domain_list_fp);
	if (!domain_list || domain_list->next == NULL) {
		fprintf(stderr, "domain name list file %s is empty\n", argv[2]);
		return 2;
	}

	if ((tun_fd = tun_alloc(tun_dev)) < 0) {
		fprintf(stderr, "tunnel device %s not exist [errno %d]\n", tun_dev, tun_fd);
		return 3;
	}

	while (1) {
		unsigned char buf[PACKET_BUF_SIZE];
		int size = capture_dns_packet(tun_fd, buf);

		unsigned char *pkt = buf + IP_HEADER_SIZE + UDP_HEADER_SIZE;
		char *dns_name = get_dns_name(size, pkt);
		if (!dns_name)
			continue;

		printf("DNS query: %s\n", dns_name);

		char *matched;
		if ((matched = match_domain_list(domain_list, dns_name))) {
			printf("Matched domain %s\n", matched);
			do_for_each_ip(pkt, size, &info);
		}
		free(dns_name);
	}
}

