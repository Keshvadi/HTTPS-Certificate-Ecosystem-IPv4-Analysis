import csv
def split_csv(start_ip_ind, end_ip_ind, start_file_ind, num_ips_per_file):
    curr_file_ind = start_file_ind
    #num_ips_per_file = (end_ip_ind - start_ip_ind + 1) // num_files
    curr_ip_csv_ind = 0
    curr_ip_in_file = 0
    curr_file = open("zmap_parts/ipv4_part" + str(curr_file_ind) + ".txt", "a+")
    with open ('full_443_scan.csv', 'rt') as csvfile:
        reader = csv.reader(csvfile)
        count = 0
        for row in reader:
            curr_ip = row[0]
            if curr_ip_csv_ind >= start_ip_ind and curr_ip_csv_ind <= end_ip_ind:
                #handle determining which file
                if curr_ip_in_file < num_ips_per_file:
                    curr_file.write(curr_ip + "\n")
                    curr_ip_in_file += 1
                elif curr_ip_in_file == num_ips_per_file:
                    #close file and reopen next
                    curr_file.close()
                    curr_file_ind += 1
                    curr_file = open("zmap_parts/ipv4_part" + str(curr_file_ind) + ".txt", "a+")
                    curr_file.write(curr_ip + "\n")

                    #reset curr_ip_in_file -- one just added
                    curr_ip_in_file = 1 
                curr_ip_csv_ind += 1
            elif curr_ip_csv_ind > end_ip_ind:
                break
    curr_file.close()

if __name__ == "__main__":
    split_csv(start_ip_ind=0, end_ip_ind=23856826, start_file_ind=0, num_ips_per_file=70)
