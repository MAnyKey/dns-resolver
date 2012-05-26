#ifndef DNS_H
#define DNS_H

#include <unistd.h>
#include <boost/variant.hpp>


#include "network_stream.hpp"

namespace dns {
namespace impl {
  
  struct header_t
  {
    uint16_t id;                // identification number

    union {
      struct {
        uint8_t rd :1;              // recursion desired
        uint8_t tc :1;              // truncated message
        uint8_t aa :1;              // authoritive answer
        uint8_t opcode :4;          // purpose of message
        uint8_t qr :1;              // query/response flag
      } bits;
      uint8_t number;
    } first_bits;

    union {
      struct {
        uint8_t rcode :4;           // response code
        uint8_t cd :1;              // checking disabled
        uint8_t ad :1;              // authenticated data
        uint8_t z :1;               // its z! reserved
        uint8_t ra :1;              // recursion available
      } bits;
      uint8_t number;
    } second_bits;

    uint16_t q_count;           // number of question entries
    uint16_t ans_count;         // number of answer entries
    uint16_t auth_count;        // number of authority entries
    uint16_t add_count;         // number of resource entries
  };

  inline network::serializer & operator<<(network::serializer & s, const header_t header)
  {
    return s << header.id << header.first_bits.number << header.second_bits.number << header.q_count << header.ans_count << header.auth_count << header.add_count;
  }

  inline network::deserializer & operator>>(network::deserializer & ds, header_t & header)
  {
    return ds >> header.id >> header.first_bits.number >> header.second_bits.number >> header.q_count >> header.ans_count >> header.auth_count >> header.add_count;
  }
    

  inline void init_header(header_t * header, uint16_t id)
  {
    header->id = id;
    header->first_bits.bits.qr = 0;                  // This is a query
    header->first_bits.bits.opcode = 0;              // This is a standard query
    header->first_bits.bits.aa = 0;                  // Not Authoritative
    header->first_bits.bits.tc = 0;                  // This message is not truncated
    header->first_bits.bits.rd = 1;                  // Recursion Desired
    
    header->second_bits.bits.ra = 0;                  // Recursion not available!
    header->second_bits.bits.z = 0;
    header->second_bits.bits.ad = 0;
    header->second_bits.bits.cd = 0;
    header->second_bits.bits.rcode = 0;
    
    header->q_count = 1;
    header->ans_count = 0;
    header->auth_count = 0;
    header->add_count = 0;
  }

  struct query_t
  {
    std::string name;
    uint16_t type;
    uint16_t qclass;
  };

  
  inline network::serializer & operator<<(network::serializer & s, const query_t & query)
  {
    return s << query.name << query.type << query.qclass;
  }

  inline network::deserializer & operator>>(network::deserializer & ds, query_t & query)
  {
    return ds >> query.name >> query.type >> query.qclass;
  }

  struct resource_record_t
  {
    std::string name;
    uint16_t type;
    uint16_t _class;
    uint32_t ttl;
    uint16_t data_len;
    boost::variant< std::string, std::vector<uint8_t> > rdata;

    enum record_type {
      T_A = 1,                  // Ipv4 address
      T_NS = 2,                 // Nameserver
      T_CNAME = 5,              // Canonical name
      T_SOA = 6,                // Start of authority zone
      T_PTR = 12,               // Domain name pointer
      T_MX = 15                 // Mail server
    };
  };
  
  inline network::deserializer & operator>>(network::deserializer & ds, resource_record_t & rr)
  {
    ds >> rr.name;
    uint16_t data_len;
    ds >> rr.type >> rr._class >> rr.ttl >> data_len;
    if (rr.type == resource_record_t::T_CNAME) {
      std::string str;
      ds >> str;
      rr.rdata = std::move(str);
    } else {
      std::vector<uint8_t> data;
      data.reserve(data_len);
      for(uint16_t i = 0; i < data_len; ++i) {
        uint8_t n;
        ds >> n;
        data.push_back(n);
      }
      rr.rdata = std::move(data);
    }
    return ds;
  }

  struct packet_t {
    header_t header;
    query_t query;
    std::vector<resource_record_t> answers;
    std::vector<resource_record_t> authority;
    std::vector<resource_record_t> additional;
  };

  inline network::serializer & operator<<(network::serializer & s, const packet_t & p)
  {
    s << p.header << p.query;
    return s;
  }

  inline network::deserializer & operator>>(network::deserializer & ds, packet_t & p)
  {
    ds >> p.header >> p.query;
    assert(p.header.q_count == 1);
    const header_t & header = p.header;;
    resource_record_t rr;
    for (size_t i = 0; i < header.ans_count; ++i) {
      ds >> rr;
      p.answers.push_back(rr);
    }
    for (size_t i = 0; i < header.auth_count; ++i) {
      ds >> rr;
      p.authority.push_back(rr);
    }
    for (size_t i = 0; i < header.add_count; ++i) {
      ds >> rr;
      p.additional.push_back(rr);
    }
    return ds;
  }
  

  inline packet_t make_query_packet(std::string name)
  {
    packet_t packet;
    init_header(&packet.header, getpid());
    packet.query.name = name;
    packet.query.type = 1;            // IPv4 address
    packet.query.qclass = 1;          // Internet
    return packet;
  }
    
}}


#endif /* DNS_H */
