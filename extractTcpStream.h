#ifndef _EXTRACTTCPSTREAM_H_
#define _EXTRACTTCPSTREAM_H_

#include <pcap.h>
#include <unistd.h>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <map>
#include <deque>
#include <algorithm>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <cassert>

void handle_packet(pcap_t *infile,const pcap_pkthdr *pkt_header,const u_char *pkt_data);
pcap_dumper_t *open_new_outfile(pcap_t *infile);
std::string uint32ip_to_str(u_int32_t ipaddr);
void usage(const char *argv0);
void increase_filehandle_limits();

//四元组，用来表示一个tcp连接
struct connection_key_t{
	u_int32_t saddr;
	u_int32_t daddr;
	u_int32_t sport;
	u_int32_t dport;

	std::string as_string() const {
		std::stringstream strstream;
		strstream << "{" << uint32ip_to_str(ntohl(this->saddr)) << ":"
		<< uint32ip_to_str(ntohl(this->daddr)) << ":" 
		<< ntohs(this->sport) << ":" << ntohs(this->dport) << "}";

		return strstream.str();
	}
};

//保存tcp流的相关信息，outfile表示该tcp流对应的保存文件句柄
//fin_rst则表示该tcp流的FIN位或RST是否已经置1
struct connection_t {
	pcap_dumper_t *outfile;
	bool fin_rst; //若为true，则表示下一SYN数据包为新连接

	connection_t(pcap_dumper_t *of):outfile(of),fin_rst(false) {}

	void close(const connection_key_t &key);
};

int debug = 0;
std::string version = "v1.0";
std::string outform("stream-%04d.pcap");
int link_layer_size = -1; //数据链路层头部长度
bool quit;
int now_open,max_open; //目前打开文件数和可以打开最大文件数
bool warn_ipv4;
bool warn_tcp;
unsigned curn = 0;

//目前处理的连接信息
std::map<connection_key_t,connection_t> conninfo;
std::deque<connection_key_t> closed;

void connection_t::close(const connection_key_t &key){
	fin_rst = true;
	if(std::find(closed.begin(),closed.end(),key) == closed.end()){
		if(debug)
			std::cerr << "Pushing on closed: " << key.as_string() << std::endl;
		closed.push_back(key);
	}
}

bool operator<(const connection_key_t a,const connection_key_t b){
	return (a.saddr < b.saddr || (a.saddr == b.saddr && (a.daddr < b.daddr || 
			(a.daddr == b.daddr && (a.sport < b.sport || (a.sport == b.sport && 
			a.dport < b.dport))))));
}

bool operator==(const connection_key_t a,const connection_key_t b){
	return  a.saddr == b.saddr && a.daddr == b.daddr &&
			a.sport == b.sport && a.dport == b.dport;	
}


void bailout(int signo){
	quit = true;
}


#endif
