import json

def parse_mult_json():
    with open('zgrab.json') as json_f:
        for json_str in json_f:
            curr_json = json.loads(json_str)
            iterate_json_keys(curr_json)

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
    keys_arr = ['timestamp']
    parse_mult_json()
    print ("done")

