import os

def form_out_files(start_ind, end_ind):
    for i in range(start_ind, end_ind + 1):
        file_path = os.path.join("zgrab_output", "zgrab_out" + str(i) + ".json")
        with open(file_path, "a+"):
            pass

if __name__ == "__main__":
    form_out_files(0, 340811)
