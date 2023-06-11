import json
import operator

total_jsons = 0
hs_success = 0
known_errors = 0
unknown_errors = 0
unknown_error_reasons = {}
known_error_reasons = {}
tls_vers = {}
browser_trusted_certs = 0
signature_algs = {}
org_names = {}
key_algs = {}

leaf_rsa_key_lens = {}
leaf_ecdsa_key_lens = {}
leaf_ecdsa_curve_types = {}

chain_rsa_key_lens = {}
chain_ecdsa_key_lens = {}
chain_ecdsa_curve_types = {}

def parse_subj_key_info(sk_info):
    curr_key_alg = sk_info["key_algorithm"]["name"]
    key_len = None
    ECDSA_curve_type = None
    if curr_key_alg == "RSA":
        key_len = sk_info["rsa_public_key"]["length"]
    elif curr_key_alg == "ECDSA":
        curr_ecdsa_pub_key = sk_info["ecdsa_public_key"]
        key_len = curr_ecdsa_pub_key["length"]
        ECDSA_curve_type = curr_ecdsa_pub_key["curve"]
    return curr_key_alg, key_len, ECDSA_curve_type

def parse_json_certs(zgrab_out_file):
    global total_jsons
    global hs_success
    global known_errors
    global unknown_errors
    global tls_vers
    global browser_trusted_certs

    with open(zgrab_out_file) as json_f:
        for json_str in json_f:
            if json_str[-2] != "}":
                break
            curr_json = json.loads(json_str)
            curr_data = curr_json["data"]
            curr_tls = curr_data["tls"]
            total_jsons += 1

            # Check TLS handshake success
            curr_hs_res = curr_tls["status"]
            if curr_hs_res == "success":
                hs_success += 1
            elif curr_hs_res == "unknown-error":
                unknown_errors += 1
                curr_error = curr_tls["error"]
                unknown_error_reasons[curr_error] = unknown_error_reasons.get(curr_error, 0) + 1
                continue
            else:
                known_errors += 1
                known_error_reasons[curr_hs_res] = known_error_reasons.get(curr_hs_res, 0) + 1
                continue

            curr_result = curr_tls["result"]
            curr_hs_log = curr_result["handshake_log"]

            # Check TLS version
            curr_tls_ver = curr_hs_log["server_hello"]["version"]["name"]
            tls_vers[curr_tls_ver] = tls_vers.get(curr_tls_ver, 0) + 1

            # Count number of browser trusted certs
            curr_server_certs = curr_hs_log["server_certificates"]
            curr_val_status = curr_server_certs["validation"]["browser_trusted"]
            if curr_val_status:
                browser_trusted_certs += 1
            else:
                continue

            # Retrieve signature alg name
            curr_parsed = curr_server_certs["certificate"]["parsed"]
            curr_alg_name = curr_parsed["signature"]["signature_algorithm"]["name"]
            signature_algs[curr_alg_name] = signature_algs.get(curr_alg_name, 0) + 1 

            # Retrieve issuer org
            curr_org_name = curr_parsed["issuer"]["organization"]
            if len(curr_org_name) > 1:
                print("more than one org name")
            org_names[curr_org_name[0]] = org_names.get(curr_org_name[0], 0) + 1

            # Get leaf key alg and length
            curr_subj_key_info = curr_parsed["subject_key_info"]
            leaf_key_alg, leaf_key_len, leaf_ecdsa_curve_type = parse_subj_key_info(curr_subj_key_info)
            if leaf_key_alg == "RSA":
                leaf_rsa_key_lens[leaf_key_len] = leaf_rsa_key_lens.get(leaf_key_len, 0) + 1
            elif leaf_key_alg == "ECDSA":
                leaf_ecdsa_key_lens[leaf_key_len] = leaf_ecdsa_key_lens.get(leaf_key_len, 0) + 1
                leaf_ecdsa_curve_types[leaf_ecdsa_curve_type] = leaf_ecdsa_curve_types.get(leaf_ecdsa_curve_type, 0) + 1
            else:
                print("other leaf key alg used: " + str(leaf_key_alg))

            # Get chain cert
            curr_chain_arr = curr_server_certs["chain"]
            for curr_chain in curr_chain_arr:
                curr_chain_subj_key = curr_chain["parsed"]["subject_key_info"]
                chain_key_alg, chain_key_len, chain_ecdsa_curve_type = parse_subj_key_info(curr_chain_subj_key)
                if chain_key_alg == "RSA":
                    chain_rsa_key_lens[chain_key_len] = chain_rsa_key_lens.get(chain_key_len, 0) + 1
                elif chain_key_alg == "ECDSA":
                    chain_ecdsa_key_lens[chain_key_len] = chain_ecdsa_key_lens.get(chain_key_len, 0) + 1
                    chain_ecdsa_curve_types[chain_ecdsa_curve_type] = chain_ecdsa_curve_types.get(chain_ecdsa_curve_type, 0) + 1
                else:
                    print("other chain key alg used: " + str(chain_key_alg))


keys_arr = None

def iterate_json_keys(obj):
    for k, v in obj.items():
        if k == 'timestamp':
            print("timestamp key found")
            print(v)
        if isinstance(v, dict):
            iterate_json_keys(v)
        else:
            if k == 'timestamp':
                print(v)
            # Handle checking for keys -- should ensure uniqueness

def sort_map(curr_map):
    return sorted(curr_map.items(), key=operator.itemgetter(1), reverse=True)

def sum_map_values(curr_map):
    return sum(list(curr_map.values()))

if __name__ == '__main__':
    total_jsons = 0
    for ind in range(340812, 681623+1):
        curr_file = "zgrab_output/zgrab_out" + str(ind) + ".json"
        parse_json_certs(curr_file)
    print("number total jsons: " + str(total_jsons))
    print("hs_success: " + str(hs_success))
    print("unknown errors: " + str(unknown_errors))
    print("known errors: " + str(known_errors))
    print("known_error_reasons: " + str(known_error_reasons))
    print("unknown_error_reasons: " + str(unknown_error_reasons))
    print()

    print("tls_vers: " + str(sort_map(tls_vers)))
    print()

    print("browser trusted certs: " + str(browser_trusted_certs))
    print()

    print("signature algs: " + str(sort_map(signature_algs)))
    print("tot sig algs: " + str(sum_map_values(signature_algs)))
    print()

    print("org_names: " + str(sort_map(org_names)))
    print("tot org names: " + str(sum_map_values(org_names)))
    print()

    print("key algs: " + str(sort_map(key_algs)))
    print("tot key algs: " + str(sum_map_values(key_algs)))
    print()

    print("leaf_rsa_key_lens: " + str(leaf_rsa_key_lens))
    print("leaf_ecdsa_key_lens" + str(leaf_ecdsa_key_lens))
    print("leaf_ecdsa_curve_types: " + str(leaf_ecdsa_curve_types))
    print("")

    print("chain_rsa_key_lens: " + str(chain_rsa_key_lens))
    print("chain_ecdsa_key_lens: " + str(chain_ecdsa_key_lens))
    print("chain_ecdsa_curve_types: " + str(chain_ecdsa_curve_types))
    print("")
