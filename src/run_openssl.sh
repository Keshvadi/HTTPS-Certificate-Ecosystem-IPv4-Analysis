#!/bin/bash
timeout=30
verification_depth=15
nhandshakes_attempted=0
nleaf=0
ntrusted=0
declare -A CAs
declare -A verify_errors

# Retrieve array of TLS IPv4 addresses
ipv4_addrs=($(python3 -c 'from parse_tls_sites import form_sites; form_sites(0, 200)' | tr -d '[],'))

outfile="a.txt"
stats_file="intermed_stats.txt"

# Get TLS version from argument
die () {
    echo >&2 "$@"
    exit 1
}
[ "$#" -eq 1 ] || die "Provide TLS version argument as 2 for 1.2, or 3 for 1.3"
if [ "$1" = "2" ]; then
    tls_version="tls1_2"
else
    tls_version="tls1_3"
fi

rm -f "$outfile"
rm -f "$stats_file"

for server in "${ipv4_addrs[@]}"; do
    curr_ip=$(echo "$server" | sed -e "s/'//g")
    echo "curr_ip: $curr_ip"
    echo -e "\n server: $server; tls version: $tls_version \n" > "$outfile" # TODO: remove this (but still create new file for each server: unless concurrency)
    echo | timeout "$timeout" openssl s_client -connect "$curr_ip:443" \
        -"$tls_version" -CAfile /etc/ssl/certs/ca-certificates.crt \
        -verify "$verification_depth" \
        &>> "$outfile"
    
    # Handshake attempted
    ((nhandshakes_attempted++))

    echo "nhandshakes_attempted: $nhandshakes_attempted, nleaf: $nleaf, ntrusted: $ntrusted \n" > "$stats_file"

    # Handshake succeeded
    if grep --quiet "BEGIN CERTIFICATE" "$outfile"; then
        ((nleaf++))
    else
        continue
    fi

    # Cert trusted
    if grep --quiet "verify error" "$outfile"; then
        continue
    else
        ((ntrusted++))
    fi

    # If got this far, it's trusted
    # TODO: record CAs
done

# Assuming every successful handshake produces a leaf cert
percent_handshakes_successful=$((100 * nleaf / nhandshakes_attempted))
percent_leaf_trusted=$((100 * ntrusted / nleaf))

echo "nhandshakes_attempted:" "$nhandshakes_attempted" ", nleaf:" "$nleaf" ", ntrusted:" "$ntrusted"
# TODO: add percentages to maps, export all variables to python
