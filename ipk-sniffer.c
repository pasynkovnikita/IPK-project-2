#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <time.h>
#include <net/ethernet.h>

// global variables
//flags
int tcp = 0, // flag for tcp packets - will only show tcp packets
udp = 0, // flag for udp packets - will only show udp packets
arp = 0, // flag for arp frames
icmp4 = 0, // flag for ICMPv4 packets
icmp6 = 0, // flag for ICMPv6 echo request/response
ndp = 0, // flag for ICMPv6 NDP packets
igmp = 0, // flag for IGMP packets
mld = 0, // flag for mld packets
packets_count = 1, // number of packets to capture - if not specified equals to 1
port = -1;  // port to filter on

char *device = NULL; // device to capture on

void validate_device(char *device_name) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    pcap_if_t *d;
    for (d = alldevs; d; d = d->next) {
        if (strcmp(d->name, device_name) == 0) {
            pcap_freealldevs(alldevs);
            return;
        }
    }
    pcap_freealldevs(alldevs);
    fprintf(stderr, "Error: device %s does not exist.\n", device_name);
    exit(EXIT_FAILURE);
}

void print_devices() {
    printf("Active devices:\n");
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    for (d = alldevs; d; d = d->next) {
        printf("%s\n", d->name);
    }
    pcap_freealldevs(alldevs);
}

void parse_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            if (i + 1 < argc) {
                device = argv[++i];
                validate_device(device);
            } else {
                print_devices();
                return;
            }
        } else if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                port = atoi(argv[++i]);
            } else {
                fprintf(stderr, "Error: -p option requires a port number.\n");
                exit(EXIT_FAILURE);
            }
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0) {
            tcp = 1;
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0) {
            udp = 1;
        } else if (strcmp(argv[i], "--icmp4") == 0) {
            icmp4 = 1;
        } else if (strcmp(argv[i], "--icmp6") == 0) {
            icmp6 = 1;
        } else if (strcmp(argv[i], "--arp") == 0) {
            arp = 1;
        } else if (strcmp(argv[i], "--ndp") == 0) {
            ndp = 1;
        } else if (strcmp(argv[i], "--igmp") == 0) {
            igmp = 1;
        } else if (strcmp(argv[i], "--mld") == 0) {
            mld = 1;
        } else if (strcmp(argv[i], "-n") == 0) {
            if (i + 1 < argc) {
                packets_count = atoi(argv[++i]);
            } else {
                fprintf(stderr, "Error: -n option requires a number.\n");

            }
        } else {
            fprintf(stderr, "Error: invalid argument: %s\n", argv[i]);
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char **argv) {
//    inits
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 0;
    int timeout_limit = 1500; /* In milliseconds */

    parse_args(argc, argv);

    return 0;
}