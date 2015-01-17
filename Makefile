default:
	gcc -g -Wall -o dnsroute dnsroute.c -lpcap

debug:
	gcc -g -Wall -DDEBUG -o dnsroute dnsroute.c -lpcap
