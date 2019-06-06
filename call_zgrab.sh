#!/bin/bash
for (( i=0; i<340812; i++ ))
do
curr_file="zmap_parts/ipv4_part"
curr_file+=$i
curr_file+=".txt"

out_file="zgrab_output/zgrab_out"
out_file+=$i
out_file+=".json"
echo | sudo $GOPATH/src/github.com/zmap/zgrab2/zgrab2 -f $curr_file tls --port 443 --output-file=$out_file --root-cas /etc/ssl/certs/ca-certificates.crt
done
printf "\n"

#test_file="test_ips.txt"
#test_out_file="test.json"
#echo | sudo $GOPATH/src/github.com/zmap/zgrab2/zgrab2 -f $test_file tls --port 443 --output-file=$test_out_file --root-cas /etc/ssl/certs/ca-certificates.crt
