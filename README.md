# IPK Project 2

## Network sniffer

## Functionality

The program is a network sniffer that captures packets on a network interface and prints information about them. It uses the `libpcap` library to capture packets. 

It allows users to:

- Specify a network interface to capture packets on.
- Filter packets based on protocol (TCP, UDP, ARP, ICMPv4, ICMPv6, IGMP, MLD).
- Filter packets based on port number for TCP or UDP protocols.
- Specify the number of packets to capture.

The program prints information about each captured packet, including its source and destination IP addresses, protocol, port number, packet type, and payload.

## Usage

The program is launched with the following command:

    ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}


The options are:

- `-i` or `--interface`: specifies the network interface to capture packets on.
- `-p`: specifies the port number to filter packets on.
- `--tcp` or `-t`: filters TCP packets only.
- `--udp` or `-u`: filters UDP packets only.
- `--arp`: filters ARP packets only.
- `--icmp4`: filters ICMPv4 packets only.
- `--icmp6`: filters ICMPv6 echo request/response only.
- `--igmp`: filters IGMP packets only.
- `--mld`: filters MLD packets only.
- `-n`: specifies the number of packets to capture.

If there were multiple options specified, the program will output packets that match any of the options. For example, for 
    
    ./ipk-sniffer -i eth0 -p 80 --tcp --udp --icmp6 -n 10

the program will output packets that match any of the following:

- TCP packets on port 80
- UDP packets on port 80
- ICMPv6 packets

## Sources

Here are some sources that were helpful for understanding `libpcap`:

- [tcpdump tutorial](https://danielmiessler.com/study/tcpdump/)
- [An introduction to libpcap](https://www.tcpdump.org/pcap.html)
- [Using libpcap in C](https://www.devdungeon.com/content/using-libpcap-c)
- [libpcap documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- [pcap-filter man page](https://www.tcpdump.org/manpages/pcap-filter.7.html)