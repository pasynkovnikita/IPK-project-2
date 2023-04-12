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

// convert time from timeval to string in format: YYYY-MM-DDTHH:MM:SS.MICROSEC+HH:MM
void get_timestamp(struct timeval time_in_tv) {
    char buffer[128];
    char time_buffer[64];
    time_t time_in_sec = time_in_tv.tv_sec;
    struct tm *time = localtime(&time_in_sec);

    strftime(time_buffer, sizeof time_buffer, "%FT%T", time);
    snprintf(buffer, sizeof buffer, "%s.%03ld", time_buffer, time_in_tv.tv_usec / 1000);

// add timezone in HH:MM format
    char timezone_buffer[6];
    char timezone_hours[2];
    char timezone_minutes[2];
    strftime(timezone_buffer, 10, "%z", time);

    strncpy(timezone_hours, timezone_buffer + 1, 2);

    strncpy(timezone_minutes, timezone_buffer + 3, 2);

    strncat(buffer, "+", 2);
    strncat(buffer, timezone_hours, 2);
    strncat(buffer, ":", 2);
    strncat(buffer, timezone_minutes, 2);

    printf("timestamp: %s\n", buffer);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
//  get packet header
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

//  print timestamp
    get_timestamp(header->ts);

}

int main(int argc, char **argv) {
//    inits
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 0;
    int timeout_limit = 1500; /* In milliseconds */
    bpf_u_int32 subnet_mask, ip;
    struct bpf_program filter;
    char filter_exp[256] = ""; // filter expression


    parse_args(argc, argv);

    pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", device, errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_lookupnet(device, &ip, &subnet_mask, errbuf) == -1) {
        printf("Could not get information for device: %s\n", device);
        ip = 0;
        subnet_mask = 0;
    }

    handle = pcap_open_live(device, 1028, 1, timeout_limit, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
        return 2;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
        return (2);
    }

    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    //    capture packets
    pcap_loop(handle, packets_count, packet_handler, NULL);

    return 0;
}