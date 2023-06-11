#!/bin/bash
for (( i=0; i<340812; i++ )); do
    curr_file="zmap_parts/ipv4_part$i.txt"
    out_file="zgrab_output/zgrab_out$i.json"
    echo | sudo $MYZGRAB -f "$curr_file" tls --port 443 --output-file="$out_file" --root-cas /etc/ssl/certs/ca-certificates.crt
done
printf "\n"
