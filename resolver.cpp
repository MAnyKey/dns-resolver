#include <fstream>
#include <sstream>
#include <iterator>
#include <iomanip>
#include <stdexcept>

#include <boost/asio/ip/udp.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/format.hpp>

#include "resolver.hpp"
#include "dns.hpp"
#include "network_stream.hpp"

namespace dns {
  
  void resolver::add_nameserver(const std::string & nameserver)
  {
    nameservers_.push_back(nameserver);
  }

  void resolver::set_nameserver(const std::string & nameserver)
  {
    nameservers_.clear();
    nameservers_.push_back(nameserver);
  }

  void resolver::set_nameservers(const std::vector<std::string> & nameservers)
  {
    nameservers_.assign(nameservers.begin(), nameservers.end());
  }
  
  void get_nameservers(std::vector<std::string> & nameservers)
  {
    std::ifstream fdns("/etc/resolv.conf", std::ifstream::in);
    std::string line;
    while (getline(fdns, line)) {
      boost::trim(line);
      if ('#' == line[0])
        continue;
      std::vector<std::string> tokens;
      boost::split(tokens, line, boost::algorithm::is_any_of(" \t"), boost::algorithm::token_compress_on);
      if (tokens.size() != 2)
        continue;
      if (tokens.front() != "nameserver")
        continue;
      nameservers.push_back(tokens.back());
    }
  }

  hostent resolver::gethostbyname(const std::string & hostname) const
  {
    using boost::asio::ip::udp;
    
    if (nameservers_.empty()) {
      get_nameservers(nameservers_);
      if (nameservers_.empty())
        throw std::runtime_error("No one nameserver");
    }
    dns::impl::packet_t packet = dns::impl::make_query_packet(hostname);
    network::serializer serializer;
    serializer << packet;

    boost::asio::io_service io_service;
    udp::socket udp_sock(io_service);
    udp_sock.open(udp::v4());
    
    udp::endpoint destination(
      boost::asio::ip::address::from_string(nameservers_.front()), 53);
    
    udp_sock.send_to(boost::asio::buffer(serializer.buffer()), destination);


    std::vector<uint8_t> input(0xffff);
    dns::impl::packet_t input_packet;
    boost::system::error_code error;
    size_t len = udp_sock.receive_from(boost::asio::buffer(input), destination, 0, error);
    if (error)
      throw std::runtime_error(str(boost::format("%1%") % error));
    if (!len)
      throw std::runtime_error("No input");
    network::deserializer deserializer(input);
    deserializer >> input_packet;

    hostent rv;
    rv.name = input_packet.query.name;

    for (auto & ans : input_packet.answers) {
      switch (ans.type) {
      case impl::resource_record_t::T_CNAME:
        rv.aliases.push_back(boost::get<std::string>(ans.rdata));
        break;
      case impl::resource_record_t::T_A:
        rv.addresses.push_back(boost::get< std::vector<uint8_t> >(ans.rdata));
        break;
      default:
        std::cerr << "Unknown type of answer: " << ans.type << std::endl;
      }
    }

    return rv;
  }

}
