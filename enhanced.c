#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

#define MAX_OCTET_VALUE 256 // Maximum value for an octet

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct iphdr *ip_header;
    int packet_count = 0;
    int octet_count[MAX_OCTET_VALUE] = {0};//Create an array of 256 values to store the number of each occurance

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
	//printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(*(struct in_addr*)&ip_header->daddr));
	
	// use a bitshift to get the last octet
	int last_octet = (ip_header->daddr >> 24); 
	// increment the value of that count in the array
	++octet_count[last_octet];

    }

    pcap_close(handle);


    // print the occurrences of each last octet values
    for(int i = 0; i < MAX_OCTET_VALUE; i++) {
	    if(octet_count[i] != -2){
		    printf("Last octet %i: %i\n",i, octet_count[i]);
            }
    }
	

    return 0;
}
