#ifndef RESOLVER_H
#define RESOLVER_H

#include <string>
#include <vector>
#include <list>
#include <cstdint>

namespace dns {
  
  struct hostent
  {
    std::string name;
    std::vector<std::string> aliases;
    std::list< std::vector<uint8_t> > addresses;
  };
  
  struct resolver
  {
    void set_nameserver(const std::string & nameserver);
    void add_nameserver(const std::string & nameserver);
    void set_nameservers(const std::vector<std::string> & nameservers);
    
    hostent gethostbyname(const std::string & hostname) const;

  private:

    enum query_type
    {
      T_A = 1,                    // Ipv4 address
      T_NS = 2,                   // Nameserver
      T_CNAME = 5,                // canonical name
      T_SOA = 6,                  // start of authority zone
      T_PTR = 12,                 // domain name pointer 
      T_MX = 15                   // Mail server
    };

    
    mutable std::vector<std::string> nameservers_;
  
  };
}

#endif /* RESOLVER_H */
