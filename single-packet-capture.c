/* 
    Sagar Jain
    geekysagarjain@gmail.com
    To compile:
    >gcc filename.c -lpcap

    Simple single packet capture program
*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <sys/types.h>
#include <time.h>

int main(int argc, char **argv)
{
    pcap_if_t *interface;  /* find an interface to use */
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */

    u_char *ptr; /* printing out hardware header info */

    // pcap_findalldevs used to find the valid interface.
    if (pcap_findalldevs(&interface, errbuf) == -1)
    {
        fprintf(stderr, "There is a problem with pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    dev=interface->name; // saving a valid interface name in dev.

    printf("DEV: %s\n",dev);

        /* open the device for sniffing.

        pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms,
        char *ebuf)

        device - We will pass the device which is captured by pcap_findalldevs
        snaplen - maximum size of packets to capture in bytes
        promisc - set card in promiscuous mode?
        to_ms   - time to wait for packets in miliseconds before read
        times out
        errbuf  - if something happens, place error string here

        Note if you change "prmisc" param to anything other than zero, you will
        get all packets your device sees, whether they are intendeed for you or
        not!! Be sure you know the rules of the network you are running on
        before you set your card in promiscuous mode!!     */

    descr = pcap_open_live(dev,BUFSIZ,0,5,errbuf); /* pcap_open_live() is used to obtain a 
                                                        packet capture handle to look at 
                                                        packets on the network */

    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }


    /*pcap_next
       grab a packet from descr (yay!)                    
       u_char *pcap_next(pcap_t *p,struct pcap_pkthdr *h) 
       so just pass in the descriptor we got from         
       our call to pcap_open_live and an allocated        
       struct pcap_pkthdr                                 */

    packet = pcap_next(descr,&hdr);

    if(packet == NULL)
    {/* dinna work *sob* */
        printf("Didn't grab packet\n");
        exit(1);
    }

    /*  struct pcap_pkthdr {
        struct timeval ts;   time stamp 
        bpf_u_int32 caplen;  length of portion present 
        bpf_u_int32;         lebgth this packet (off wire) 
        }
     */

    printf("Grabbed packet of length %d\n",hdr.len);
    printf("Recieved at ..... %s\n",ctime((const time_t*)&hdr.ts.tv_sec)); 
    printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

    /* lets start with the ether header... 
    
    struct ether_header
    {
        uint8_t  ether_dhost[ETH_ALEN];	    destination eth addr
        uint8_t  ether_shost[ETH_ALEN];	    source ether addr
        uint16_t ether_type;		        packet type ID field
    } __attribute__ ((__packed__));
    */
    eptr = (struct ether_header *) packet;

    /* Do a couple of checks to see what packet type we have..*/
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
    {
        printf("Ethernet type hex:%x dec:%d is an IP packet\n", ntohs(eptr->ether_type), ntohs(eptr->ether_type));
    }
    
    else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    {
        printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));
    }
    
    else
    {
        printf("Ethernet type %x not IP", ntohs(eptr->ether_type));
        exit(1);
    }

    /* copied from Steven's UNP */
    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN; // 6-byte

    printf("Destination Address:");
    do
    {
        printf("%s%X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++); // need to understand this part. 
    }while(--i>0);
    printf("\n");

    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN; 

    printf("Source Address:");
    do
    {
        printf("%s%X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");

    return 0;
}