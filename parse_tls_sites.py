import csv
def form_sites(start_ind, end_excl_ind):
    sites = []
    with open ('p443_partial_zmap.csv', 'rb') as csvfile:
        reader = csv.reader(csvfile)
        count = 0
        for row in reader:
	    if count == end_excl_ind:
	        break
	    sites.append(row[0])
	    count += 1
    sites = sites[start_ind:end_excl_ind]
    print (sites)
    #return sites

