#include "extractTcpStream.h"

using namespace std;

int main(int argc,char **argv){
	increase_filehandle_limits();
	int c;
	while((c = getopt(argc,argv,"hdo:l")) != -1){
		switch(c)
		{
		case 'd':
			debug++;break;
		case 'o':
			outform = optarg;break;
		case 'l':
			link_layer_size = atoi(optarg);break;
		case 'h':
		default:
			usage(argv[0]);break;
		}
	}

	if(optind >= argc)
		usage(argv[0]);
	
	string fname = argv[optind];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *infile = pcap_open_offline(fname.c_str(),errbuf);
	if(!infile){
		cerr << "Cannot open infile: " <<errbuf << endl;
		exit(1);
	}

	if(link_layer_size == -1){
		int link_type = pcap_datalink(infile);
		//判断数据链路层类型
		switch(link_type){
		case DLT_RAW:
			link_layer_size = 0;break;
		case DLT_NULL:
			link_layer_size = 4;break;
		case DLT_EN10MB:
			link_layer_size = 14;break;
		case DLT_LINUX_SLL:
			link_layer_size = 16;break;
		default:
			cerr << "Cannot determine size of link layer\n";
			cerr << "Use -l <link_layer_size> to force a link layer size\n";
			exit(1);
		}
	}

	struct bpf_program fp;
	//编译BPF过滤器过滤规则
	if(pcap_compile(infile,&fp,"tcp",1,PCAP_NETMASK_UNKNOWN) == -1){
		cerr << "Compile filter rules error\n";
		exit(1);
	}
	//设置过滤器过滤规则
	if(pcap_setfilter(infile,&fp) == -1){
		cerr << "Set filter rules error\n";
		exit(1);
	}

	signal(SIGINT,bailout);
	signal(SIGTERM,bailout);
	signal(SIGQUIT,bailout);

	int rc;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	while(!quit && (rc = pcap_next_ex(infile,&pkt_header,&pkt_data))== 1)
		handle_packet(infile,pkt_header,pkt_data);
	
	map<connection_key_t,connection_t>::iterator it;
	for(it = conninfo.begin();it != conninfo.end();it++)
		pcap_dump_close(it->second.outfile);

	if(rc == -1){
		pcap_perror(infile,(char *)"Reading packet error\n");
		exit(1);
	}

	return 0;
}

//将整形ip地址转换为点分十进制字符串ip
string uint32ip_to_str(u_int32_t ipaddr){
	char buf[16];
	sprintf(buf,"%d.%d.%d.%d",(ipaddr >> 24),((ipaddr >> 16) & 0xff),
			((ipaddr >> 8) & 0xff),(ipaddr & 0xff));
	return buf;
}

//用法说明
void usage(const char *argv0){
	cerr << "extractTcpStream " << version << "(c) 2015 Taylor\n\n";
	cerr << "usage: " << argv0 << " [-h] [-d] [-o format] <pcapfile>\n\n"
		 << "format defaults to '" << outform << "'\n\n";
	exit(EXIT_FAILURE);
}

//设置进程能够打开的文件数量
void increase_filehandle_limits(){
	/*
	struct rlimit{
		rlim_t rlim_cur;//为指定的资源指定当前的系统软限制
		rlim_t rlim_max;//为指定的资源指定当前的系统硬限制
	};
	*/
	struct rlimit rlim;
	
	//RLIMIT_NOFILE指定进程最多可以打开的文件数
	if(getrlimit(RLIMIT_NOFILE,&rlim)){
		cerr << "getrlimit error\n";
		exit(EXIT_FAILURE);
	}

	rlim.rlim_cur = rlim.rlim_max;
	
	//输出文件数要少于允许打开的文件数，因为需要留出足够的空间
	//给stdin,stdout,stdcerr和输入文件等等
	max_open = rlim.rlim_cur - 10;

	if(setrlimit(RLIMIT_NOFILE,&rlim)){
		cerr << "setlimit error\n";
		exit(EXIT_FAILURE);
	}

}

//数据包处理,提取四元组
void handle_packet(pcap_t *infile,const pcap_pkthdr *pkt_header,const u_char *pkt_data){
	const iphdr *ip_header = reinterpret_cast<const iphdr*>(pkt_data+link_layer_size);
	
	//只处理IPv4数据包
	if(ip_header->version != 4){
		if(!warn_ipv4){
			cerr << "Can only handle IPv4\n";
			warn_ipv4 = true;
		}
		return;
	}

	if(ip_header->protocol != IPPROTO_TCP){
		if(!warn_tcp){
			cerr << "The Protocol is not tcp\n";
			warn_tcp = true;
		}
		return;
	}

	const tcphdr *tcp_header = reinterpret_cast<const tcphdr*>(pkt_data+link_layer_size+sizeof(iphdr));

	//四元组格式，saddr > daddr，如果 saddr < daddr则交换，并且交换对应的端口
	//这样A ---> B的数据包和B ---> A的数据包四元组就保持一致
	connection_key_t key = {ip_header->saddr,ip_header->daddr,
					tcp_header->source,tcp_header->dest};
	if(ip_header->saddr < ip_header->daddr){
		key = {ip_header->daddr,ip_header->saddr,
			  tcp_header->dest,tcp_header->source};
	}

	connection_t *conn;
	map<connection_key_t,connection_t>::iterator it = conninfo.find(key);
	if(it == conninfo.end()){
		conn = &(conninfo.insert(make_pair(key,connection_t(open_new_outfile(infile)))).first->second);
		if(debug)
			cerr << "Opened outfile for " << key.as_string() << endl;
	}
	else{
		conn = &(it->second);
		
		//如果数据包SYN位置1，且四元组对应的连接已出现过FIN或RST位置1
		//则关闭对应连接的文件，打开一个新文件存储新连接
		if(tcp_header->syn && conn->fin_rst){
			pcap_dump_close(conn->outfile);
			it->second = connection_t(open_new_outfile(infile));
			conn = &(it->second);
			if(debug)
				cerr << "Opened new outfile for reused connection " << 
				key.as_string() << endl;
		}
	}
	
	//保存流数据
	pcap_dump((u_char*)conn->outfile,pkt_header,pkt_data);
	if(tcp_header->fin || tcp_header->rst)
		conn->close(key);
}

//打开一个新文件，用来存储新的TCP流的数据
pcap_dumper_t *open_new_outfile(pcap_t *infile){
	if(debug)
		cerr << "Opening new dumpfile (" << now_open <<")\n";

	//如果打开的文件数超过了限制的最大文件数
	//则关闭最先创建的文件
	if(now_open >= max_open){
		if(debug)
			cerr << "Closing some file\n";
		if(closed.size()){
			connection_key_t key = closed.front();
			closed.pop_front();
			map<connection_key_t,connection_t>::iterator it = conninfo.find(key);
			if(it == conninfo.end()){
				cerr << key.as_string();
				assert(it != conninfo.end());
			}
			if(debug)
				cerr << "Closing " << it->second.outfile << endl;
			pcap_dump_close(it->second.outfile);
			assert(conninfo.erase(key));
			now_open--;
		}
		else
			cerr << "No file close. Will probably soon run out of filehandles.\n";
	}

	now_open++;
	char fname[1024];
	snprintf(fname,sizeof(fname),outform.c_str(),curn++);
	pcap_dumper_t *outfile = pcap_dump_open(infile,fname);
	if(debug)
		cerr << "Opened " << outfile << endl;
	if(!outfile){
		pcap_perror(infile,(char *)"Cannot open outfile: ");
		exit(1);
	}

	return outfile;
}

