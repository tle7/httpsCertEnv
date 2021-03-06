#!/bin/bash
timeout=30
verification_depth=15
nhandshakes_attempted=0
nleaf=0
ntrusted=0
declare -A CAs 
declare -A verify_errors

#retrieve array of TLS IPv4 addrs
ipv4_addrs=($(python3 -c'from parse_tls_sites import form_sites; form_sites(0, 200)' | tr -d '[],'))

outfile="a.txt"
stats_file="intermed_stats.txt"
# get TLS version from arg
die () {
    echo >&2 "$@"
    exit 1
}
[ "$#" -eq 1 ] || die "provide TLS version argument as 2 for 1.2, or 3 for 1.3"
if [ $1 = "2" ]; then
    tls_version="tls1_2"
else
    tls_version="tls1_3"
fi

rm -f $outfile 
rm -f $stats_file
#declare -a servers=("github.com" "www.google.com") 
#declare -a servers=("github.com")
#declare -a servers=("192.30.255.113") # github
#declare -a servers=("feistyduck.com")
#declare -a servers=("104.154.89.105") # same for all badssl according to nc
#self-signed.badssl.com 
#declare -a servers=("expired.badssl.com")

for server in ${ipv4_addrs[@]}; do
#for server in ${servers[@]}; do
    curr_ip=`echo $server | sed -e "s/'//g"`
    echo "curr_ip: $curr_ip"
    echo -e "\n server: $server; tls version: $tls_version \n" > $outfile # TODO: remove this (but still create new file for each server: unless concurrency)
    echo | timeout $timeout openssl s_client -connect $curr_ip:443 \
        -$tls_version -CAfile /etc/ssl/certs/ca-certificates.crt \
        -verify $verification_depth \
        &>> $outfile 
    # will this ever crash e.g. if handshake fails for a given server?
    # TODO: echo separates openssl from shell - need to make sure it's done before parse the output 
    
    # handshake attempted
    let nhandshakes_attempted+=1
    
    echo "nhandshakes_attempted: $nhandshakes_attempted, nleaf: $nleaf, ntrusted: $ntrusted \n" > $stats_file 
    # handshake succeeded
    if grep --quiet "BEGIN CERTIFICATE" $outfile; then # tested, at least for feistyduck.com
        let nleaf+=1
         # sounds like stdout and file are same speed
    else
        continue
    fi

    # cert trusted
    if grep --quiet "verify error" $outfile; then
        #TODO: only get first match 
        # left off: ug how do I do this, which line exactly to grep for (see result of expired);
        # if multiple errors, get all? (see if paper did)
        #error_line=$(grep --quiet "verify error")
        #: read error_num <<< $error_line
        #let verify_errors[]+=1
        continue
    else
        let ntrusted+=1
    fi
    
    # if got this far, it's trusted
    # TODO: record CAs
done

# assuming every successful handshake produces a leaf cert 
let percent_handshakes_successful=100*nleaf/nhandshakes_attempted
let percent_leaf_trusted=100*ntrusted/nleaf

echo "nhandshakes_attempted:" $nhandshakes_attempted ", nleaf:" $nleaf ", ntrusted:" $ntrusted
# TODO: add percentages to maps, export all variables to python
