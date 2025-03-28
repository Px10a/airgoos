#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <pcap.h>
#include <getopt.h>

#define CHUNK_SIZE 100000
#define MAX_THREADS 10

typedef struct {
    char *ssid;
    char *bssid;
    int handshake;
} Network;

void calculate_pmkid(unsigned char *pmk, unsigned char *ap_mac, unsigned char *sta_mac, unsigned char *pmkid) {
    unsigned char data[256];
    strcpy((char *)data, "PMK Name");
    memcpy(data + strlen("PMK Name"), ap_mac, 6);
    memcpy(data + strlen("PMK Name") + 6, sta_mac, 6);

    unsigned int len = 0;
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, pmk, 32, EVP_sha1(), NULL);
    HMAC_Update(ctx, data, strlen("PMK Name") + 12);
    HMAC_Final(ctx, pmkid, &len);
    HMAC_CTX_free(ctx);
}

void find_pw_chunk(char **pw_list, size_t pw_count, unsigned char *ssid, unsigned char *ap_mac, unsigned char *sta_mac, unsigned char *captured_pmkid, int *stop_flag) {
    for (size_t i = 0; i < pw_count; i++) {
        if (*stop_flag) {
            break;
        }
        char *password = pw_list[i];
        unsigned char pmk[32];
        PKCS5_PBKDF2_HMAC(password, strlen(password), ssid, strlen((char *)ssid), 4096, EVP_sha1(), 32, pmk);
        
        unsigned char pmkid[16];
        calculate_pmkid(pmk, ap_mac, sta_mac, pmkid);
        
        printf("[%s] Vyzkoušené klíče: %zu/%zu - %s\n", __TIME__, i + 1, pw_count, password);

        if (memcmp(pmkid, captured_pmkid, 16) == 0) {
            printf("[+] HESLO NALEZENO!  [%s\n]", password);
            *stop_flag = 1;
            break;
        } else {
            printf("Zkouším heslo: %s\n", password);
        }
    }
}

void list_networks(const char *pcapfile, Network **networks, size_t *network_count) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    handle = pcap_open_offline(pcapfile, errbuf);
    if (handle == NULL) {
        printf("[!] Error opening pcap file: %s\n", errbuf);
        return;
    }

    struct pcap_pkthdr header;
    const u_char *packet;
    *network_count = 0;

    while ((packet = pcap_next(handle, &header)) != NULL) {
        if (packet[0] == 0x80) {
            // Beacon frame processing
            Network net;
            net.ssid = (char *)(packet + 36);
            net.bssid = (char *)(packet + 10);
            net.handshake = 0;
            networks[*network_count] = (Network *)malloc(sizeof(Network));
            memcpy(networks[*network_count], &net, sizeof(Network));
            (*network_count)++;
        }
    }

    pcap_close(handle);
}

void *thread_worker(void *args) {
    // Unpack the arguments
    char **pw_list = ((char ***)args)[0];
    size_t pw_count = ((size_t *)args)[1];
    unsigned char *ssid = ((unsigned char **)args)[2];
    unsigned char *ap_mac = ((unsigned char **)args)[3];
    unsigned char *sta_mac = ((unsigned char **)args)[4];
    unsigned char *captured_pmkid = ((unsigned char **)args)[5];
    int *stop_flag = ((int *)args)[6];

    find_pw_chunk(pw_list, pw_count, ssid, ap_mac, sta_mac, captured_pmkid, stop_flag);
    return NULL;
}

int main(int argc, char *argv[]) {
    int workers = 10;
    char *wordlist = NULL;
    char *pcapfile = NULL;
    
    int opt;
    while ((opt = getopt(argc, argv, "P:t:")) != -1) {
        switch (opt) {
            case 'P':
                wordlist = optarg;
                break;
            case 't':
                workers = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s -P WORDLIST -t THREADS capture.pcap\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    pcapfile = argv[optind];
    if (wordlist == NULL || pcapfile == NULL) {
        fprintf(stderr, "Usage: %s -P WORDLIST -t THREADS capture.pcap\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    Network *networks[10];
    size_t network_count = 0;
    list_networks(pcapfile, networks, &network_count);

    if (network_count == 0) {
        printf("[!] No networks found in the capture file.\n");
        return 1;
    }

    Network selected_network = *networks[0];
    printf("[*] Selected network: %s | %s\n", selected_network.ssid, selected_network.bssid);
    if (!selected_network.handshake) {
        printf("[!] No handshake found, unable to crack.\n");
        return 1;
    }

    unsigned char bssid[6];
    unsigned char ssid[32];
    unsigned char captured_pmkid[16];

    memcpy(bssid, selected_network.bssid, 6);
    memcpy(ssid, selected_network.ssid, strlen(selected_network.ssid));
    
    FILE *file = fopen(wordlist, "r");
    if (file == NULL) {
        perror("Error opening wordlist");
        return 1;
    }

    size_t pw_count = 0;
    char *pw_list[CHUNK_SIZE];
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        pw_list[pw_count] = strdup(line);
        pw_count++;
    }

    fclose(file);

    pthread_t threads[MAX_THREADS];
    int stop_flag = 0;
    size_t chunk_size = pw_count / workers;

    for (int i = 0; i < workers; i++) {
        void *args[7] = {pw_list, &chunk_size, ssid, bssid, bssid, captured_pmkid, &stop_flag};
        pthread_create(&threads[i], NULL, thread_worker, (void *)args);
    }

    for (int i = 0; i < workers; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
