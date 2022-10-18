/* 
    Sagar Jain
    To compile:
    >gcc filename.c -lpcap

    Looks for an interface, and lists the network ip
    and mask associated with that interface.
*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
    char *dev;  /* name of the device to use */
    char *net;  /* dot notation of the network address */
    char *mask; /* dot notation of the network mask    */
    int ret;    /* return code */
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;  /* ip          */
    bpf_u_int32 maskp; /* subnet mask */
    struct in_addr addr;

    /* ask pcap_lookupdev to find a valid device for use to sniff on */

    dev = pcap_lookupdev(errbuf); // pcap_lookupdev used to find the valid interface.

    /* error checking */
    if (dev == NULL)
    {
        printf("%s\n", errbuf); // if pcap_lookupdev did not find any device it will save the error message in errbuf.
        exit(1);
    }

    /* print out device name */
    printf("DEV: %s\n", dev);

    /* ask pcap_lookupnet for the network address and mask of the device but not in human readable form*/
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    /* get the network address in a human readable form */
    addr.s_addr = netp;    // saving netp value in the addr.s_addr struct.
    net = inet_ntoa(addr); // inet_ntoa convert Internet number in IN to ASCII representation.

    if (net == NULL) /* thanks Scott :-P */
    {
        perror("inet_ntoa");
        exit(1);
    }

    printf("NET: %s\n", net); // Now printing the IPaddr into human readable form

    /* do the same as above for the device's mask */
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);

    if (mask == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }

    printf("MASK: %s\n", mask);

    return 0;
}