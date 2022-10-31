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


void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    static int count = 1;
    fprintf(stdout,"%d, ",count);
    fflush(stdout);
    count++;    
}

int main(int argc,char **argv)
{ 
    pcap_if_t *interface;  /* find an interface to use */
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */


    if(argc != 2)
    { 
        fprintf(stdout,"Usage: %s \"filter program\"\n",argv[0]);
        return 0;
    }

    // pcap_findalldevs used to find the valid interface.
    if (pcap_findalldevs(&interface, errbuf) == -1)
    {
        fprintf(stderr, "There is a problem with pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    dev=interface->name; // saving a valid interface name in dev

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    /* open device for reading this time lets set it in promiscuous
     * mode so we can monitor traffic to another machine             */
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { 
        printf("pcap_open_live(): %s\n",errbuf); 
        exit(1); 
    }

    /* 
    Lets try and compile the program.. non-optimized 
    pcap_compile() is used to compile the string str into a filter program. 
    See pcap-filter(7) for the syntax of that string. 
    program is a pointer to a bpf_program struct and is filled in by pcap_compile()
    */
    if(pcap_compile(descr,&fp,argv[1],0,netp) == -1)
    { 
        fprintf(stderr,"Error calling pcap_compile\n"); 
        exit(1); 
    }

    /* 
    set the compiled program as the filter 
    pcap_setfilter() is used to specify a filter program. 
    fp is a pointer to a bpf_program struct, usually the result of a call to pcap_compile().
    */
    if(pcap_setfilter(descr,&fp) == -1)
    { 
        fprintf(stderr,"Error setting filter\n"); 
        exit(1); 
    }

    /* ... and loop */ 
    pcap_loop(descr,-1,my_callback,NULL);

    return 0;
}