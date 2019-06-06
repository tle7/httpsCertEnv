
def form_out_files(start_ind, end_ind):
    for i in range(start_ind, end_ind + 1):
        curr_file = open("zgrab_output/zgrab_out" + str(i) + ".json", "a+")
        curr_file.close()

if __name__ == "__main__":
    form_out_files(0, 340811)
