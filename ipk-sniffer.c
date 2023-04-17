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
#include <getopt.h>

// macros to add expression to filter
// @param expression - expression to add
// @param filter - filter to add expression to
// @param ignore_or - flag to ignore "or"
#define ADD_TO_FILTER_EXPRESSION(expression, filter, ignore_or) \
        if (strlen(filter) > 0) { \
            if (!ignore_or) { \
            strcat(filter, " or "); \
            } \
        } \
        strcat(filter, expression); \

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

// device validation
// @param device_name - name of the device
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

// port validation
void validate_port() {
    if (port < 0 || port > 65535) {
        fprintf(stderr, "Error: invalid port number: %d", port);
        exit(EXIT_FAILURE);
    }
}

// print all available devices
void print_devices() {
    printf("\n");
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

// parse command line arguments
// @param argc - number of arguments
// @param argv - array of arguments
void parse_args(int argc, char **argv) {
    // exit if no arguments were given
    if (argc == 1) {
        print_devices();
        exit(0);
    }

    struct option long_options[] = {
            {"interface", optional_argument, NULL, 'i'},
            {"tcp",       no_argument, &tcp,       1},
            {"udp",       no_argument, &udp,       1},
            {"arp",       no_argument, &arp,       1},
            {"icmp4",     no_argument, &icmp4,     1},
            {"icmp6",     no_argument, &icmp6,     1},
            {"igmp",      no_argument, &igmp,      1},
            {"mld",       no_argument, &mld,       1},
            {NULL, 0,                        NULL, 0}
    };
    int opt, option_index;

    while ((opt = getopt_long(argc, argv, "i::p:tun:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                // if -i is given without argument, print all available devices and exit
                if (argv[optind] == NULL) {
                    if (argc == 2) {
                        print_devices();
                        exit(0);
                    } else {
                        fprintf(stderr, "Error: no device specified.\n");
                        exit(EXIT_FAILURE);
                    }
                }
                device = argv[optind];
                validate_device(device);
                break;
            case 'p':
                port = atoi(optarg);
                validate_port();
                break;
            case 't':
                tcp = 1;
                break;
            case 'u':
                udp = 1;
                break;
            case 'n':
                packets_count = atoi(optarg);
                break;
            case '?':
                exit(EXIT_FAILURE);
            default:
                break;
        }
    }

    if (device == NULL) {
        fprintf(stderr, "Error: no device specified.\n");
        exit(EXIT_FAILURE);
    }
}

// convert time from timeval to string in format: YYYY-MM-DDTHH:MM:SS.MICROSEC+HH:MM
// @param time_in_tv - time in timeval format
void print_timestamp(struct timeval time_in_tv) {
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

void print_mac_addresses(uint8_t *ether_shost, uint8_t *ether_dhost) {
    printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ether_shost[0], ether_shost[1], ether_shost[2],
           ether_shost[3], ether_shost[4], ether_shost[5]);
    printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ether_dhost[0], ether_dhost[1], ether_dhost[2],
           ether_dhost[3], ether_dhost[4], ether_dhost[5]);
}

// print IP addresses
// @param packet - pointer to the beginning of the packet
// @param ether_type - ether type of the packet
void print_ip_addresses(u_char *packet, uint16_t ether_type) {
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    uint16_t protocol = ntohs(ether_type);
    // find IP addresses depending on the ether type
    if (protocol == ETHERTYPE_IP) {
        inet_ntop(AF_INET, packet + 26, src_ip, INET_ADDRSTRLEN);   // ip addresses on 26 and 30 bytes of the packet
        inet_ntop(AF_INET, packet + 30, dst_ip, INET_ADDRSTRLEN);
    } else if (protocol == ETHERTYPE_IPV6) {
        inet_ntop(AF_INET6, packet + 22, src_ip, INET6_ADDRSTRLEN); // ip addresses on 22 and 38 bytes of the packet
        inet_ntop(AF_INET6, packet + 38, dst_ip, INET6_ADDRSTRLEN);
    } else if (protocol == ETHERTYPE_ARP) {
        inet_ntop(AF_INET, packet + 28, src_ip, INET_ADDRSTRLEN);   // ip addresses on 28 and 38 bytes of the packet
        inet_ntop(AF_INET, packet + 38, dst_ip, INET_ADDRSTRLEN);
    }

    if (protocol == ETHERTYPE_IP || protocol == ETHERTYPE_IPV6 || protocol == ETHERTYPE_ARP) {
        printf("src IP: %s\n", src_ip);
        printf("dst IP: %s\n", dst_ip);
    }
}

// print ports
// @param packet - pointer to the beginning of the packet
// @param ether_type - ether type of the packet
void print_ports(const u_char *packet, uint16_t ether_type) {
    char src_port[6];
    char dst_port[6];

    uint16_t protocol = ntohs(ether_type);
    // find ports depending on the ether type
    if (protocol == ETHERTYPE_IP) {
        // print ports only if IP protocol is TCP or UDP
        if (packet[23] == IPPROTO_TCP || packet[23] == IPPROTO_UDP) {   // byte 23 is IPv4 protocol
            snprintf(src_port, 6, "%d", ntohs(*(uint16_t *) (packet + 34)));    // ports on bytes 34 and 36
            snprintf(dst_port, 6, "%d", ntohs(*(uint16_t *) (packet + 36)));

            printf("src port: %s\n", src_port);
            printf("dst port: %s\n", dst_port);
        }
    } else if (protocol == ETHERTYPE_IPV6) {
        // print ports only if IP protocol is TCP or UDP
        if (packet[20] == IPPROTO_TCP || packet[20] == IPPROTO_UDP) {   // byte 20 is IPv6 protocol
            snprintf(src_port, 6, "%d", ntohs(*(uint16_t *) (packet + 54)));    // ports on bytes 54 and 56
            snprintf(dst_port, 6, "%d", ntohs(*(uint16_t *) (packet + 56)));

            printf("src port: %s\n", src_port);
            printf("dst port: %s\n", dst_port);
        }
    }
}


// print packet data in hex and ascii
// @param packet - pointer to packet data
// @param size - size of packet data
void print_packet_data(const u_char *packet, uint32_t size) {
    printf("\n");

    int symbols_printed = 0;    // number of symbols printed in current line to help print data in the last line

    for (int i = 0; i < size; i++) {
        // print address in hex
        if (i % 16 == 0) {
            printf("0x%04x: ", i);
            symbols_printed = 0;
        }
        symbols_printed++;

        printf("%02x ", packet[i]); // print packet data in hex

        if (i % 16 == 15) {
            // print packet data in ascii
            for (int j = i - 15; j <= i; j++) {
                // spaces after every 8 symbols
                if (j % 8 == 0 && j != i - 15) {
                    printf(" ");
                }

                // print only printable characters
                if (packet[j] >= 32 && packet[j] <= 126) {
                    printf("%c", packet[j]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
        }
    }

    // print packet data in ascii for last line
    if (symbols_printed % 16 != 0) {
        for (int i = 0; i < 16 - symbols_printed; i++) {
            printf("   ");
        }
        for (uint32_t i = size - symbols_printed; i < size; i++) {
            if (i % 8 == 0 && i != size - symbols_printed) {
                printf(" ");
            }
            if (packet[i] >= 32 && packet[i] <= 126) {
                printf("%c", packet[i]);
            } else {
                printf(".");
            }
        }
    }

    printf("\n\n");
}

// callback function for pcap_loop
// @param args - user supplied argument
// @param header - pointer to the pcap_pkthdr structure
// @param packet - pointer to the packet data
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
//  get packet header
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

//  print timestamp
    print_timestamp(header->ts);

//  print source and destination mac addresses
    print_mac_addresses(eth_header->ether_shost, eth_header->ether_dhost);

//    print frame length
    printf("frame length: %d bytes\n", header->len);

//  print src and dst IP addresses
    print_ip_addresses((u_char *) packet, eth_header->ether_type);

//  print ports
    print_ports((u_char *) packet, eth_header->ether_type);

//  print payload data
    print_packet_data(packet, header->len);
}

// create a filter expression for pcap_setfilter
// @param filter_exp - filter expression
void set_filter(char *filter_exp) {
    // add port to filter expression
    if (port != -1) {
        char port_str_buf[16];
        snprintf(port_str_buf, 16, "port %d", port);
        ADD_TO_FILTER_EXPRESSION(port_str_buf, filter_exp, 0)

        // if both tcp and udp are set or both are unset, get both to filter
        if (tcp && udp || !tcp && !udp) {
            ADD_TO_FILTER_EXPRESSION(" and (tcp or udp)", filter_exp, 1)
        }
            // if only tcp or udp is set, get only that protocol
        else if (tcp) {
            ADD_TO_FILTER_EXPRESSION(" and tcp", filter_exp, 1)
        } else if (udp) {
            ADD_TO_FILTER_EXPRESSION(" and udp", filter_exp, 1)
        }
    } else {
        // if port is not set just get tcp or udp
        if (tcp) {
            ADD_TO_FILTER_EXPRESSION("tcp", filter_exp, 0)
        }
        if (udp) {
            ADD_TO_FILTER_EXPRESSION("udp", filter_exp, 0)
        }
    }

    // add icmpv4 to filter expression
    if (icmp4) {
        ADD_TO_FILTER_EXPRESSION("icmp", filter_exp, 0)
    }

    // add icmpv6 echo request/response to filter expression
    if (icmp6) {
        ADD_TO_FILTER_EXPRESSION("icmp6 and (icmp6[0] == 128 or icmp6[0] == 129)", filter_exp, 0)
    }

    // add arp to filter expression
    if (arp) {
        ADD_TO_FILTER_EXPRESSION("arp", filter_exp, 0)
    }

    // add ndp to filter expression
    if (ndp) {
        ADD_TO_FILTER_EXPRESSION(
                "icmp6 and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137 or icmp6[0] == 148 or icmp6[0] == 149)",
                filter_exp, 0)
    }

    if (igmp) {
        ADD_TO_FILTER_EXPRESSION("igmp", filter_exp, 0)
    }

    if (mld) {
        ADD_TO_FILTER_EXPRESSION(
                "icmp6 and (icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132 or icmp6[0] == 143)",
                filter_exp, 0)
    }
}


int main(int argc, char **argv) {
//    inits
    char errbuf[PCAP_ERRBUF_SIZE];
    int timeout_limit = 1500; /* In milliseconds */
    bpf_u_int32 subnet_mask, ip;
    struct bpf_program filter;
    char filter_exp[256] = ""; // filter expression

//    parse arguments and get all the flags
    parse_args(argc, argv);

//    create filter expression
    set_filter(filter_exp);

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

//    close the handle
    pcap_close(handle);

    return 0;
}