/* 
    Sagar Jain
    geekysagarjain@gmail.com
    To compile:
    >gcc filename.c -lpcap

    Simple multiple packet capture and filter program.
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

/* callback function that is passed to pcap_loop(..) and called each time 
 * a packet is recieved */

int global_argc;

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    static int count = 1;
    for (; count <= global_argc; count++)
    {
        printf("Called %d Time\n", count);
    }
    
}

int main(int argc,char **argv)
{ 
    global_argc=atoi(argv[1]);
    pcap_if_t *interface;  /* find an interface to use */
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */

    if(argc != 2)
    {
        fprintf(stdout,"Usage: %s numpackets\n",argv[0]);
        return 0;
    }

    // pcap_findalldevs used to find the valid interface.
    if (pcap_findalldevs(&interface, errbuf) == -1)
    {
        fprintf(stderr, "There is a problem with pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    dev=interface->name; // saving a valid interface name in dev.

    /* open device for reading */
    descr = pcap_open_live(dev,BUFSIZ,0,5,errbuf);
    if(descr == NULL)
    { 
        printf("pcap_open_live(): %s\n",errbuf); 
        exit(1); 
    }

    /* allright here we call pcap_loop(..) and pass in our callback function */
    // Collects and processes packets.
    /* int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)*/
    /* If you are wondering what the user argument is all about, so am I!!   */

    pcap_loop(descr,atoi(argv[1]),my_callback,NULL);

    fprintf(stdout,"\nDone processing packets...\n");
    return 0;
}