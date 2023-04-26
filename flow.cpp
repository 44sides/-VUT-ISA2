#include <stdio.h>
#include <unistd.h> 
#include <stdlib.h>
#include <string.h>
#include <iostream>  
#include <cmath>
#include <vector>
using namespace std;  

#include <arpa/inet.h>
#include <netdb.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/stat.h>
#include <sys/socket.h>

#include <pcap.h>
#include <pcap/pcap.h>

#include <errno.h>
#include <err.h>

#include <time.h>

#define SIZE_ETHERNET   14
#define SIZE_NF_HEADER   24
#define SIZE_NF_RECORD   48

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define PACKET_SIZE 1464

/* Structures */
typedef struct record_flow
{
	uint32_t srcaddr;
	uint32_t dstaddr;
	uint32_t nexthop;
	uint16_t input;
	uint16_t output;
	uint32_t dPkts;
	uint32_t dOctets;
	uint32_t First;
	uint32_t Last;
	uint16_t srcport;
	uint16_t dstport;
	uint8_t pad1;
	uint8_t tcp_flags;
	uint8_t prot;
	uint8_t tos;
	uint16_t src_as;
	uint16_t dst_as;
	uint8_t	src_mask;
	uint8_t dst_mask;
	uint16_t pad2;
} record_flow;

typedef struct header_flow
{
	uint16_t version;
	uint16_t count;
	uint32_t SysUptime;
	uint32_t unix_secs;
	uint32_t unix_nsecs;
	uint32_t flow_sequence;
	uint8_t engine_type;
	uint8_t engine_id;
	uint16_t sampling_interval;
} header_flow;

/* Global variables */
char collectorHost[253], collectorPort[6];
double activeTimer_ms, inactiveTimer_ms; int flow_maxCount;

time_t boot_time_sec; suseconds_t boot_time_usec; bool boot_time_set = false;

vector<record_flow> flow_cache;

int flow_seq = 0;

struct timeval tv_last; // timeval of the last packet
time_t sysuptime_last; // sysuptime of the last packet

int sock;                        // socket descriptor
struct sockaddr_in server;		 // address structure of the server
struct hostent *servent;         // network host entry required by gethostbyname()  

/**
 * Fills a buffer with flows. 
 * @param flow_export vector of the flows to be exported
 * @param number number of flows to be written to the buffer
 * @param buffer buffer to be filled with flows
 * @return the number written
 */
int fill_buffer_flows(vector<record_flow> *flow_export, int number, u_char *buffer);

/**
 * Composes and writes the header. 
 * @param tv timeval struct of the packet header
 * @param sysuptime SysUptime
 * @param flows_count count of flows to be exported
 * @param buffer buffer to be filled with the composed header
 */
void fill_buffer_header(const struct timeval tv, time_t sysuptime, int flows_count, u_char *buffer);

/**
 * Exporting flows to a collector.
 * @param tv timeval struct of the packet header
 * @param sysuptime SysUptime
 * @param flow_export vector of the flows to be exported
 */
void send_netflow_packets(const struct timeval tv, time_t sysuptime, vector<record_flow> *flow_export);

/**
 * Goes through the flow cache to add a packet and export flows if needed.
 * @param packet binary packet
 * @param sysuptime SysUptime
 * @param flow_export vector of the flows to be exported
 */
void flow_cache_loop(const u_char *packet, time_t sysuptime, vector<record_flow> *flow_export);

/**
 * Converts the needed variables to the network byte order.
 * @param rec a flow
 */
void record_net_byte_order(record_flow *rec);

/**
 * Processes captured packets. It is called by pcap_loop().
 * @param agrs arguments 
 * @param header header of a packet
 * @param packet binary packet
 */
void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	if (!boot_time_set) { boot_time_sec = header->ts.tv_sec; boot_time_usec = header->ts.tv_usec; boot_time_set = true; }
	time_t sysuptime = (header->ts.tv_sec - boot_time_sec) * (double)1000 + round((header->ts.tv_usec - boot_time_usec) / (double)1000);	// SysUpTime calculation

	vector<record_flow> flow_export;
	int flows_count;

	flow_cache_loop(packet, sysuptime, &flow_export);											// go through the flow cache and filling the vector with flows to export
	flows_count = flow_export.size();

	if (flows_count != 0)
	{
		send_netflow_packets(header->ts, sysuptime, &flow_export);								// exporting flows sending netflow packets to a collector

		flow_seq += flows_count;
	}

	// Values for the residual export
	tv_last.tv_sec = header->ts.tv_sec;
	tv_last.tv_usec = header->ts.tv_usec;
	sysuptime_last = sysuptime;
}

void flow_cache_loop(const u_char *packet, time_t sysuptime, vector<record_flow> *flow_export)
{
	vector<record_flow>::iterator it;
	record_flow record;
	bool added = false;
	bool instant_export = false;

	const struct ip *my_ip = (struct ip*) (packet + SIZE_ETHERNET);									// pointing to the beginning of IP header
	
	uint16_t sport = 0, dport = 0; // icmp packet
	uint8_t tcp_flags_packet = 0;

	if ((int)my_ip->ip_p != 1) // tcp or udp packet
	{
		const struct tcphdr *my_tcp = (struct tcphdr*) (packet + SIZE_ETHERNET + my_ip->ip_hl*4);	// pointing to the beginning of TCP header
		sport = my_tcp->th_sport;
		dport = my_tcp->th_dport;

		if((int)my_ip->ip_p == 6) // tcp packet
		{
			tcp_flags_packet = my_tcp->th_flags;

			if (tcp_flags_packet & TH_FIN || tcp_flags_packet & TH_RST)
				instant_export = true;
		}
	}

	time_t active_time, inactive_time;
	for (it = flow_cache.begin(); it != flow_cache.end(); ++it)
	{
		active_time = sysuptime - (*it).First; inactive_time = sysuptime - (*it).Last;

		if (active_time < activeTimer_ms && inactive_time < inactiveTimer_ms)
		{
			if (my_ip->ip_src.s_addr == (*it).srcaddr && my_ip->ip_dst.s_addr == (*it).dstaddr && sport == (*it).srcport && dport == (*it).dstport && my_ip->ip_p == (*it).prot && my_ip->ip_tos == (*it).tos)
			{
				//cout << "add to the flow:" << endl;
				added = true;

				(*it).dPkts ++;
				(*it).dOctets += ntohs(my_ip->ip_len);
				(*it).Last = sysuptime;
				(*it).tcp_flags = (*it).tcp_flags | tcp_flags_packet;

				if(instant_export)
				{
					flow_export->push_back(*it);
					flow_cache.erase(it); it--;
				}
			}
		}
		else
		{
			//cout << "export the flow (timers)" << endl;
			flow_export->push_back(*it);
			flow_cache.erase(it); it--;
		}
	}

	if (!added)
	{
		//cout << "add to the flow cache" << endl;
		record = {my_ip->ip_src.s_addr, my_ip->ip_dst.s_addr, 0, 0, 0, 1, ntohs(my_ip->ip_len), (uint32_t)sysuptime, (uint32_t)sysuptime, sport, dport, 0, tcp_flags_packet, my_ip->ip_p, my_ip->ip_tos, 0, 0, 0, 0, 0};

		flow_cache.push_back(record);

		if(instant_export)
		{	
			it = flow_cache.end(); it--;

			flow_export->push_back(*it);
			flow_cache.erase(it); it--; 
		}
	}

	if (int(flow_cache.size()) > flow_maxCount)
	{
		//cout << "export the oldest flow" << endl;
		it = flow_cache.begin();

		flow_export->push_back(*it);
		flow_cache.erase(it); it--;
	}
}

void fill_buffer_header(const struct timeval tv, time_t sysuptime, int flows_count, u_char *buffer)
{
	header_flow *headerf = (header_flow *) (buffer);

	*headerf = {htons(5), htons(flows_count), htonl(sysuptime), htonl(tv.tv_sec), htonl(tv.tv_usec * 1000), htonl(flow_seq), 0, 0, 0};
}

int fill_buffer_flows(vector<record_flow> *flow_export, int number, u_char *buffer)
{
	int counter = 0;

	for (auto it = flow_export->begin(); it != flow_export->end() && counter != number; ++it)
	{	
		record_net_byte_order(&*it);
		memcpy(buffer + counter*SIZE_NF_RECORD, &*it, SIZE_NF_RECORD);

		flow_export->erase(it); it--;
		counter++;
	}

	return counter;
}

void record_net_byte_order(record_flow *rec)
{
	rec->dPkts = htonl(rec->dPkts);
	rec->dOctets = htonl(rec->dOctets);
	rec->First = htonl(rec->First);
	rec->Last = htonl(rec->Last);
}

void send_netflow_packets(const struct timeval tv, time_t sysuptime, vector<record_flow> *flow_export)
{	
	int flows_count = flow_export->size(); int number;
	u_char buffer[PACKET_SIZE];

	while(flows_count != 0)
	{
		if (flows_count >= 30)
		{
			number = 30;
			fill_buffer_header(tv, sysuptime, number, buffer);					// filling the buffer with the header
			fill_buffer_flows(flow_export, number, buffer + SIZE_NF_HEADER);	// processing and filling the buffer with flows
			flows_count -= number;

			sendto(sock, buffer, SIZE_NF_HEADER + number*SIZE_NF_RECORD, 0, (struct sockaddr *)&server, sizeof(server));
		}
		else
		{
			number = flows_count;
			fill_buffer_header(tv, sysuptime, number, buffer);	
			fill_buffer_flows(flow_export, number, buffer + SIZE_NF_HEADER);
			flows_count -= number;

			sendto(sock, buffer, SIZE_NF_HEADER + number*SIZE_NF_RECORD, 0, (struct sockaddr *)&server, sizeof(server));
		}
	}
}

int main(int argc, char **argv)
{
/*
 * Parsing of arguments
 */
	char pcapName[255]; string stringAddr, stringHost, stringPort; int pos;
	bool pcapNameSET = false, collectorAddrSET = false, collectorPortSET = false, timerActiveSET = false, timerInactiveSET = false, maxCountSET = false;

	int opt;
	while((opt = getopt(argc, argv, ":f:c:a:i:m:")) != -1) 
{	 
	switch(opt) 
	{ 
		case 'f':
			memcpy(pcapName, optarg, strlen(optarg) + 1);
			pcapNameSET = true;
			break;
		case 'c': 
			stringAddr = optarg;
			pos = stringAddr.find(":");

			if (pos != (int)string::npos){
				collectorPortSET = true;
				stringHost = stringAddr.substr(0, pos);
				stringPort = stringAddr.substr(pos + 1);

				strcpy(collectorHost, stringHost.c_str());
				strcpy(collectorPort, stringPort.c_str());
			}
			else{
				strcpy(collectorHost, stringAddr.c_str());
			}
			collectorAddrSET = true;
			break; 
		case 'a':
			activeTimer_ms = atof(optarg)*1000;
			timerActiveSET = true;
			break; 
		case 'i':
			inactiveTimer_ms = atof(optarg)*1000;
			timerInactiveSET = true;
			break;
		case 'm':
			flow_maxCount = stoi(optarg);
			maxCountSET = true;
			break;  
        case ':': 
            printf("Option needs a value\n"); 
			printf("Use [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n"); 
			return 1;
		case '?': 
			printf("Unknown option: -%c\n", optopt);
			printf("Use [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n"); 
			return 1;
	} 
}

if(optind < argc){
	printf("Use ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n"); 
	return 1;
}

	if(!pcapNameSET) { memcpy(pcapName, "-", 1 + 1); }
	if(!collectorAddrSET) { strcpy(collectorHost, "127.0.0.1"); }
	if(!collectorPortSET) { strcpy(collectorPort, "2055"); collectorPortSET = true;}
	if(!timerActiveSET) { activeTimer_ms = 60.0*1000; }
	if(!timerInactiveSET) { inactiveTimer_ms = 10.0*1000; }
	if(!maxCountSET) { flow_maxCount = 1024; }

/*
 * Composing server address structure and creating client socket
 */
	memset(&server,0,sizeof(server));								// erase the server structure
	server.sin_family = AF_INET;   

	if ((servent = gethostbyname(collectorHost)) == NULL)			// make DNS resolution using gethostbyname()
		errx(1,"gethostbyname() failed\n");   

	memcpy(&server.sin_addr, servent->h_addr, servent->h_length);	// copy address to the server.sin_addr structure

	server.sin_port = htons(atoi(collectorPort)); 					// server port (network byte order)

	if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)			// create a client socket
		err(1,"socket() failed\n");

/*
 * Sniffing of packets with a filtering
 */
	char errbuf[PCAP_ERRBUF_SIZE];  	// constant defined in pcap.h
  
 	struct bpf_program fp;          	// the compiled filter
  
	pcap_t *handle;                 	// packet capture handle 

  	// open a 'savefile' for reading
  	if ((handle = pcap_open_offline(pcapName,errbuf)) == NULL)
    	err(1,"pcap_open_offline() failed");

  	// compile the filter
  	if (pcap_compile(handle,&fp,"icmp or tcp or udp",0,PCAP_NETMASK_UNKNOWN) == -1)
    	err(1,"pcap_compile() failed");
  
  	// set the filter to the packet capture handle
  	if (pcap_setfilter(handle,&fp) == -1)
    	err(1,"pcap_setfilter() failed");

  	// packets are processed in turn by function mypcap_handler() in the infinite loop
  	if (pcap_loop(handle,-1,mypcap_handler,NULL) == -1)
    	err(1,"pcap_loop() failed");

  	// close the capture device and deallocate resources
  	pcap_close(handle);

/*
 * Exporting remaining flows in the flow cache.
 */
	int residue_size = flow_cache.size();

	if (residue_size > 0)
		send_netflow_packets(tv_last, sysuptime_last, &flow_cache);

printf("Successfully!\n");
return 0;
}