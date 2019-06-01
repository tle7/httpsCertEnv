import json

total_jsons = 0
hs_success = 0
known_errors = 0
unknown_errors = 0
known_error_reasons = {}
tls_1_0 = 0
tls_1_2 = 0
tls_1_3 = 0
browser_trusted_certs = 0
signature_algs = {}

def parse_json_certs(zgrab_out_file):
    global total_jsons
    global hs_success
    global known_errors
    global unknown_errors
    global tls_1_0
    global tls_1_2
    global tls_1_3
    global browser_trusted_certs

    with open(zgrab_out_file) as json_f:
        for json_str in json_f:
            curr_json = json.loads(json_str)
            curr_data = curr_json["data"]
            curr_tls = curr_data["tls"]
            total_jsons += 1

            #check tls handshake success
            curr_hs_res = curr_tls["status"]
            if curr_hs_res == "success":
                hs_success += 1
            elif curr_hs_res == "unknown-error":
                unknown_errors += 1
                continue
            else:
                known_errors += 1 #TODO: check what this field looks like and retrieve errors
                known_error_reasons[curr_hs_res] = known_error_reasons.get(curr_hs_res, 0) + 1
                continue

            curr_result = curr_tls["result"]
            curr_hs_log = curr_result["handshake_log"]
            #check TLS version
            curr_tls_ver = curr_hs_log["server_hello"]["version"]["name"]
            if curr_tls_ver == "TLSv1.2":
                tls_1_2 += 1
            elif curr_tls_ver == "TLSv1.0":
                tls_1_0 += 1
            else:
                print (curr_tls_ver)

            #count number browser trusted certs
            curr_server_certs = curr_hs_log["server_certificates"]
            curr_val_status = curr_server_certs["validation"]["browser_trusted"]
            if curr_val_status == True:
                browser_trusted_certs += 1
            else:
                continue

            #retrieve signature alg name
            curr_alg_name = curr_server_certs["certificate"]["parsed"]["signature"]["signature_algorithm"]["name"]
            signature_algs[curr_alg_name] = signature_algs.get(curr_alg_name, 0) + 1 




keys_arr = None
def iterate_json_keys(obj):
    for k,v in obj.items():
        if k == 'timestamp':
            print ("timestamp key found")
            print(v)
        if isinstance(v, dict):
            iterate_json_keys(v)
        else:
            if k == 'timestamp':
                print(v)
            #handle checking for keys -- should encure unique


if __name__=='__main__':
    total_jsons = 0
    for ind in range(0, 4+1):
        curr_file = "../curr_zgrab_jsons/zgrab_full_scan_s" + str(ind) + ".json" 
        parse_json_certs(curr_file)
    print ("number total jsons: " + str(total_jsons))
    print ("hs_success: " + str(hs_success))
    print ("unknown errors: " + str(unknown_errors))
    print ("known errors: " + str(known_errors))
    print ("known_error_reasons: " + str(known_error_reasons))
    print ("tls_1_2: " + str(tls_1_2))
    print ("tls_1_0: " + str(tls_1_0))
    print ("browser trusted certs: " + str(browser_trusted_certs))
    print ("signature algs: " + str(signature_algs))

