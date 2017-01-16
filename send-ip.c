#include <stdio.h>           // printf
#include <string.h>          // memset
#include <stdlib.h>          // for exit(0)
#include <errno.h>           // for errno
#include <unistd.h>          // for getopt()
#include <time.h>            // for nanosleep()
// ethernet, ip and tcp headers
#include <netinet/ether.h>   // provides declarations for ethernet header
#include <netinet/tcp.h>     // provides declarations for tcp header
#include <netinet/ip.h>      // provides declarations for ip header
// used for getting the mac address
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
// pcap lib
#include <pcap.h>


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
    fprintf(stderr, "usage: %s -i <interface> -m <dst-mac-address> -s <src-ipv4-address> -d <dst-ipv4-address> -n <pkts-num> -l <pkt-len> -r <speed 1-5>\n", proc);
}
extern int opterr;

int main(int argc, char* argv[]) 
{
    char* if_name = NULL;
    char* dest_mac = NULL;
    char source_host[128]={0};
    char dest_host[128]={0};
    unsigned int pkts_num = 0;
    unsigned int pkt_len = 0;
    unsigned int speed = 0;
    int opt;

    opterr = 0;

    // input arguments
    while((opt = getopt(argc, argv, "s:d:i:m:n:l:r:h")) != -1)
    {
        switch(opt)
        {
        case 'h':
            print_usage(argv[0]);
            return (1);
        case 'i':
            if_name = optarg;
            break;
        case 'm':
            dest_mac = optarg;
            break;
        case 's':
            if (sscanf(optarg, "%[^:]", source_host) != 1)
            {
                print_usage(argv[0]);
                return (1);
            }
            break;
        case 'd':
            if (sscanf(optarg, "%[^:]", dest_host) != 1)
            {
                print_usage(argv[0]);
                return (1);
            }
            break;
        case 'n':
            pkts_num = atoi(optarg); 
            break;
        case 'l':
            pkt_len = atoi(optarg);
            break;
        case 'r':
            speed = atoi(optarg);
            break;
        default:
            print_usage(argv[0]);
            return (1);
        }
    }
    
    if (if_name == NULL || dest_mac == NULL || 
        source_host[0] == 0 || dest_host[0] == 0 ||
        pkts_num == 0 || pkt_len == 0 || speed == 0)
    {
        print_usage(argv[0]); return (1);
    }

    char buffer[pkt_len];
    memset(buffer, 0x90, pkt_len);

    struct ethhdr* ether = (struct ethhdr*)buffer;
    const size_t ether_size = sizeof(struct ethhdr);
    struct iphdr* iph = (struct iphdr*)(buffer + ether_size);

    // build ethernet header
    memcpy(ether->h_source, get_mac_address(if_name), ETH_ALEN);
    struct ether_addr tmp_addr;
    ether_aton_r(dest_mac, &tmp_addr);
    memcpy(ether->h_dest, tmp_addr.ether_addr_octet, ETH_ALEN);
    ether->h_proto = htons(ETH_P_IP);

    // fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof (struct iphdr));
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      // set to 0 before calculating checksum
    iph->saddr = inet_addr(source_host);
    iph->daddr = inet_addr(dest_host);
    // ip checksum
    iph->check = csum ((unsigned short*)iph, sizeof (struct iphdr));
     
    // Open a PCAP packet capture descriptor for the specified interface
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';

    pcap_t* pcap = pcap_open_live(if_name, pkt_len, 1, 1000, pcap_errbuf);

    if (pcap_errbuf[0] != '\0') 
    {
        fprintf(stderr, "failed to open pcap\n");
        fprintf(stderr, "%s\n", pcap_errbuf);
    }
    if (!pcap) 
    {
        exit(1);
    }

    struct timespec interval, rem;
    switch(speed)
    {
        case 1:
            interval.tv_sec = 1;
            interval.tv_nsec = 0 * 1000 * 1000;
            break;
        case 2:
            interval.tv_sec = 0;
            interval.tv_nsec = 100 * 1000 * 1000;
            break;
        case 3:
            interval.tv_sec = 0;
            interval.tv_nsec = 10 * 1000 * 1000;
            break;
        case 4:
            interval.tv_sec = 0;
            interval.tv_nsec = 1 * 1000 * 1000;
            break;
        case 5:
            interval.tv_sec = 0;
            interval.tv_nsec = 0 * 1000 * 1000;
            break;
        default:
            print_usage(argv[0]);
            return (1);
    }
    
    unsigned int i;
    for ( i = 0; i <= pkts_num; i++)
    {
        int bytes = pcap_inject(pcap, buffer, pkt_len);
        nanosleep(&interval, &rem);
        if (bytes == -1) 
        {
            fprintf(stderr, "failed to inject packet\n");
            pcap_perror(pcap,0);
            pcap_close(pcap);
            exit(1);
        }
        else if (bytes != pkt_len)
        {
            fprintf(stderr, "only %d bytes were written to device\n", bytes);
        }
    } 
    
    // Close the PCAP descriptor
    pcap_close(pcap);
    return 0;
}
