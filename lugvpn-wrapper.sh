#!/bin/bash
cd `dirname $0`
mkdir -p /var/log/dnsroute
pkill dnsroute # kill all running instances
for intf in tun{0..5}; do
	./dnsroute $intf paper-sites.txt 10007 202.141.176.126 >>/var/log/dnsroute/dnsroute-$intf.log 2>&1 &
done
