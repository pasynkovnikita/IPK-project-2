## Implemented functions

Main function:

    int main(int argc, char **argv)

In the main function, we initialize the filters, parse arguments, and open device for capturing packets.

To parse arguments, we have a function called `parse_args`:

    void parse_args(int argc, char **argv)

It uses `getopt_long` function and `option` struct to parse arguments and set the global flags and variables. Here we
also check if the input given by user was valid.

To create the filter we have a function called `set_filter`:

    void set_filter(char *filter_exp)

Depending on the flags set by user, we create a filter expression and set the filter. To add filters we
use `ADD_TO_FILTER_EXPRESSION` macros, since we have to check if the filter expression is empty or not, and if we need
to add `"or"` to the beginning of a new filter.
Then we use `pcap_compile` function to compile the filter expression and `pcap_setfilter` function to set the filter.

Then we start capturing packets with the `pcap_loop` function. It uses our function `packet_handler` as a callback
function:

        void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)

It shows all the packet data, and for each type of data we have a function:

- `print_timestamp(struct timeval time_in_tv)` - prints out the time of the packet
- `print_mac_addresses(uint8_t *ether_shost, uint8_t *ether_dhost)` - prints out the source and destination MAC
  addresses
- `print_ip_addresses(u_char *packet, uint16_t ether_type)` - prints out the source and destination IP addresses. For
  different protocols IP addresses are stored in different places in the packet header, so we have to check the protocol
  type.
- `print_ports(const u_char *packet, uint16_t ether_type)` - prints out the source and destination port numbers. For
  TCP, UDP and ARP
  protocols port numbers are stored in different places in the packet header, so we have to check the protocol type.
  Every other protocol does not have port numbers, so we don't print anything.
- 