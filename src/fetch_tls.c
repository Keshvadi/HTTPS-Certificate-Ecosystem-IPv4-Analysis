#include "get_tls_sites.h"
#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#define NUM_TLS_SITES 47713654
#define IP_ADDR_LEN 18 //account for \n
#define HTTPS_PORT 443

struct sockaddr_in* get_tls_sites(int num_sites) { //if -1, return all sites
    if (num_sites == -1)
        num_sites = NUM_TLS_SITES;

    //init array of struct sockaddr_in
    struct sockaddr_in* arr = calloc(num_sites, sizeof(struct sockaddr_in));
    if (!arr) {
        printf("could not allocate array for sockaddr sites\n");
        return NULL;
    }

    //process ip addrs
    char ip_buf[IP_ADDR_LEN];
    FILE* fp = fopen("custom_csv_file.csv", "r");
    if (!fp) {
        printf("could not open csv file\n");
        free(arr);
        return NULL;
    }

    char* fgets_ret = NULL;
    for (int i = 0; i < num_sites; i++) {
        fgets_ret = fgets(ip_buf, IP_ADDR_LEN, fp);
        if (!fgets_ret) {
            printf("reading csv finished early");
            break;
        }

        size_t curr_ip_len = strlen(ip_buf);
        if (ip_buf[curr_ip_len - 1] == '\n')
            ip_buf[curr_ip_len - 1] = '\0';

        printf("curr ip addr: %s\n", ip_buf);

        struct sockaddr_in* curr_in = &arr[i];
        curr_in->sin_family = AF_INET;
        curr_in->sin_addr.s_addr = inet_addr(ip_buf);
        curr_in->sin_port = htons(HTTPS_PORT);
    }

    fclose(fp);
    return arr;
}
