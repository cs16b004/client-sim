#ifndef _dpdkdef_h_
#define _dpdkdef_h_

#include <arpa/inet.h>
#include <assert.h>
#include <ifaddrs.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sstream>
#include <string>
#define n_likely(x)       __builtin_expect((x),1)
#define n_unlikely(x)     __builtin_expect((x),0)


static constexpr uint16_t IPEtherType = 0x800;
static constexpr uint16_t IPHdrProtocol = 0x11;
static constexpr uint16_t EtherTypeIP = 0x800;
static constexpr uint16_t IPProtUDP = 0x11;

#define IP_DEFTTL 64 /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN 0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define IP_ADDR_FMT_SIZE 15

/// Check a condition at runtime. If the condition is false, throw exception.
static inline void rt_assert(bool condition, std::string throw_str, char* s) {
  if (n_unlikely(!condition)) {
    throw std::runtime_error(throw_str + std::string(s));
  }
}

/// Check a condition at runtime. If the condition is false, throw exception.
static inline void rt_assert(bool condition, std::string throw_str) {
  if (n_unlikely(!condition)) throw std::runtime_error(throw_str);
}

/// Check a condition at runtime. If the condition is false, throw exception.
/// This is faster than rt_assert(cond, str) as it avoids string construction.
static inline void rt_assert(bool condition) {
  if (n_unlikely(!condition)) throw std::runtime_error("Error");
}

/// Convert a MAC string like "9c:dc:71:5b:32:90" to an array of bytes
static void mac_from_str(const char* str, uint8_t* mac) {
  sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2],
      &mac[3], &mac[4], &mac[5]);
}

static std::string mac_to_string(const uint8_t* mac) {
  std::ostringstream ret;
  for (size_t i = 0; i < 6; i++) {
    ret << std::hex << static_cast<uint32_t>(mac[i]);
    if (i != 5) ret << ":";
  }
  return ret.str();
}
static std::string mac_to_string(struct rte_ether_addr *mac) {
  char mac_str[18];
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2],
            mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5]);
          return std::string(mac_str);

}
static uint32_t ipv4_from_str(const char* ip) {
  uint32_t addr;
  int ret = inet_pton(AF_INET, ip, &addr);
  rt_assert(ret == 1, "inet_pton() failed for " + std::string(ip));
  return addr;
}

static std::string ipv4_to_string(uint32_t ipv4_addr) {
  char str[128];
  const char* ret = inet_ntop(AF_INET, &ipv4_addr, str, sizeof(str));
  //rt_assert(ret !=nullptr, "inet_ntop failed");
  str[INET_ADDRSTRLEN - 1] = 0;  // Null-terminate
  return std::string(str);
}



static void gen_eth_header(rte_ether_hdr* eth_header, const uint8_t* src_mac,
                           const uint8_t* dst_mac) {
  
  rte_ether_addr s_adr ;
  rte_ether_addr d_adr ;
  
  memcpy(s_adr.addr_bytes, src_mac, 6);
  memcpy(d_adr.addr_bytes, dst_mac, 6);
  memcpy(&(eth_header->dst_addr),&d_adr,sizeof(rte_ether_addr));
  memcpy(&(eth_header->src_addr),&s_adr,sizeof(rte_ether_addr));
   eth_header->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
}

/// Format the IPv4 header for a UDP packet. Note that \p data_size is the
/// payload size in the UDP packet.

static void inline gen_ipv4_header(rte_ipv4_hdr* ipv4_hdr, uint32_t src_ip,
                            uint32_t dst_ip, uint16_t data_size) {

  	/**< type of service */
	ipv4_hdr->total_length = htons(sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + data_size);	/**< length of packet */
	
	
    ipv4_hdr->version_ihl = IP_VHL_DEF;
    ipv4_hdr->type_of_service = 0;
   ipv4_hdr->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
    ipv4_hdr->time_to_live = IP_DEFTTL;
    ipv4_hdr->next_proto_id = IPPROTO_UDP;
    ipv4_hdr->packet_id = 4;


	  ipv4_hdr->src_addr = src_ip;		/**< source address */
	  ipv4_hdr->dst_addr = dst_ip;	                 

    ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + data_size);
}

/// Format the UDP header for a UDP packet. Note that \p data_size is the
/// payload size in the UDP packet.
static void gen_udp_header(rte_udp_hdr* udp_hdr, uint16_t src_port,
                           uint16_t dst_port, uint16_t data_size) {
  udp_hdr->src_port = htons(src_port);
  udp_hdr->dst_port = htons(dst_port);
  udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + data_size);

 
} 

#endif
