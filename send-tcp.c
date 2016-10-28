// based on ecample: "Send an arbitrary Ethernet frame using libpcap" (c) 2012 Graham Shaw 
// http://www.microhowto.info/howto/send_an_arbitrary_ethernet_frame_using_libpcap.html
// and also taken from raw TCP packets code by Silver Moon (m00n.silv3r@gmail.com)

#include <stdio.h>           // printf
#include <string.h>          // memset
#include <stdlib.h>          // for exit(0)
#include <errno.h>           // for errno
#include <unistd.h>          // for getopt()
// ethernet, ip and tcp headers
#include <netinet/ether.h>   // provides declarations for ethernet header
#include <netinet/tcp.h>     // provides declarations for tcp header
#include <netinet/ip.h>      // provides declarations for ip header
// used for getting the mac address
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
// pcap lib
#include <pcap.h>

/* 
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

/*
 * checksum routine for Internet Protocol family headers (C Version)
 *   (based upon a version written by Mike Muuss, BRL)
 */
int csum(unsigned short *addr, int len)
{
    register int nleft = len;
    register unsigned short *w = addr;
    register int sum = 0;
    unsigned short answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w ;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return answer;
}


/* vlan header structure */
struct vlan_ethhdr {
    unsigned char   h_dest[ETH_ALEN];
    unsigned char   h_source[ETH_ALEN];
    __be16          h_vlan_proto;
    __be16          h_vlan_TCI;
    __be16          h_vlan_encapsulated_proto;
 };

// note that this is non-reentrant
char* get_mac_address(const char* if_name)
{
    static struct ifreq ifr;
    size_t if_name_len = strlen(if_name);
    if (if_name_len < sizeof(ifr.ifr_name)) 
    {
        memcpy(ifr.ifr_name,if_name,if_name_len);
        ifr.ifr_name[if_name_len]=0;
    } 
    else 
    {
        fprintf(stderr, "interface name (%s) is too long", if_name);
        return 0;
    }

    // open an IPv4-family socket for use when calling ioctl
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) 
    {
        perror(0);
        return 0;
    }

    // obtain the source MAC address, copy into ethernet header
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) 
    {
        perror(0);
        close(fd);
        return 0;
    }
    close(fd);
    return (char*)ifr.ifr_hwaddr.sa_data;
}

void print_usage(const char* proc)
{
    fprintf(stderr, "usage: %s -i <interface> -m <dst-mac-address> -s <src-ipv4-address>:<port> -d <dst-ipv4-address>:<port> [-f <tcp-flag>] [-q <tcp-seq-num>] [-v <vlan-tag>]\n", proc);
}
extern int opterr;

int main(int argc, char* argv[]) 
{
    const char* if_name = NULL;
    const char* dest_mac = NULL;
    const char source_host[128]={0};
    const char dest_host[128]={0};
    unsigned source_port = 999999;
    unsigned dest_port = 999999;
    int vlan_tag = 0;
    int opt;

    opterr = 0;

    // input arguments
    while((opt = getopt(argc, argv, ":s:d:i:m:f:q:v:h")) != -1)
    {
        switch(opt)
        {
        case 'h':
            print_usage(argv[0]); return (1);
        case 'i':
            if_name = optarg; break;
        case 'm':
            dest_mac = optarg; break;
        case 's':
            if (sscanf(optarg, "%[^:]:%u", source_host, &source_port) != 2)
            {
                print_usage(argv[0]); return (1);
            }
            break;
        case 'd':
            if (sscanf(optarg, "%[^:]:%u", dest_host, &dest_port) != 2)
            {
                print_usage(argv[0]); return (1);
            }
            break;
        case 'f':
            break;
        case 'q':
            break;
        case 'v':
            vlan_tag = atoi(optarg); break;
            break;
        default:
            print_usage(argv[0]); return (1);
        }
    }
    
    if (if_name == NULL || dest_mac == NULL || source_host[0] == 0 || dest_host[0] == 0 ||
        source_port == 999999 || dest_port == 999999)
    {
        print_usage(argv[0]); return (1);
    }

    const int PCKT_LEN = 1024;
    char buffer[PCKT_LEN];
    memset(buffer, 0, PCKT_LEN);

    struct ethhdr* ether = (struct ethhdr*)buffer;
    const size_t ether_size = (vlan_tag > 0) ? sizeof(struct vlan_ethhdr) : sizeof(struct ethhdr);
    struct iphdr* iph = (struct iphdr*)(buffer + ether_size);
    struct tcphdr* tcph = (struct tcphdr*)(buffer + ether_size + sizeof(struct iphdr));

    // build ethernet header
    memcpy(ether->h_source, get_mac_address(if_name), ETH_ALEN);
    struct ether_addr tmp_addr;
    ether_aton_r(dest_mac, &tmp_addr);
    memcpy(ether->h_dest, tmp_addr.ether_addr_octet, ETH_ALEN);
    ether->h_proto = htons(ETH_P_IP);

    if (vlan_tag > 0)
    {
        struct vlan_ethhdr* vlan_ether = (struct vlan_ethhdr*)buffer;
        // most fields are already set
        vlan_ether->h_vlan_proto = htons(ETH_P_8021Q);
        vlan_ether->h_vlan_TCI = htons(vlan_tag);
        vlan_ether->h_vlan_encapsulated_proto = htons(ETH_P_IP);
    }
        
    // fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr));
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      // set to 0 before calculating checksum
    iph->saddr = inet_addr(source_host);
    iph->daddr = inet_addr(dest_host);
    // ip checksum
    iph->check = csum ((unsigned short*)iph, sizeof (struct iphdr));
     
    // TCP header
    tcph->source = htons((unsigned short)source_port);
    tcph->dest = htons((unsigned short)dest_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;  // tcp header size
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (5840); // maximum allowed window size
    tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;
     
    // the TCP checksum
    struct pseudo_header psh;
    psh.source_address = inet_addr(source_host);
    psh.dest_address = inet_addr(dest_host);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));
     
    const int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char pseudogram[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
    tcph->check = csum((unsigned short*)pseudogram , psize);

    // Open a PCAP packet capture descriptor for the specified interface
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';

    pcap_t* pcap = pcap_open_live(if_name, PCKT_LEN, 1, 1000, pcap_errbuf);

    if (pcap_errbuf[0] != '\0') 
    {
        fprintf(stderr, "failed to open pcap\n");
        fprintf(stderr, "%s\n", pcap_errbuf);
    }
    if (!pcap) 
    {
        exit(1);
    }

    // Write the Ethernet frame to the interface
    const int expected_bytes = ether_size + sizeof(struct iphdr) + sizeof(struct tcphdr);
    int bytes = pcap_inject(pcap, buffer, expected_bytes);
    if (bytes == -1) 
    {
        fprintf(stderr, "failed to inject packet\n");
        pcap_perror(pcap,0);
        pcap_close(pcap);
        exit(1);
    }
    else if (bytes != expected_bytes)
    {
        fprintf(stderr, "only %d bytes were written to device\n", bytes);
    }
    else
    {
        fprintf(stdout, "TCP packet injected\n");
    }

    // Close the PCAP descriptor
    pcap_close(pcap);
    return 0;
}

