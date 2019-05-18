#!/bin/bash

#rm output.txt
declare -a servers=("github.com" "www.google.com") # TODO: will this be IP addr or hostname?
#declare -a servers=("github.com")
declare -a tls_versions=("tls1_2" "tls1_3") 

#retrieve array of TLS IPv4 addrs
ipv4_addrs=($(python -c'from parse_tls_sites import form_sites; form_sites(0, 50000)' | tr -d '[],'))

for tls_version in ${tls_versions[@]}; do
    #for server in ${servers[@]}; do
    for server in ${ipv4_addrs[@]}; do
	echo ${server} >> ip_out_test2.txt

        #echo -e "\n server: $server; tls version: $tls_version \n" >> output.txt 
        echo | openssl s_client -connect $server:443 \
            -$tls_version -CAfile /etc/ssl/certs/ca-certificates.crt -showcerts &>> output.txt
        # TODO: path to root certs may depend on OS (try on cloud)
        # will this ever crash e.g. if handshake fails for a given server?
        # separate out cert info and other info (e.g. keylen)?
        # how to add to root store? (just add pem's to cafile?) how to reorder? need to x509 and verify?
    done
done
