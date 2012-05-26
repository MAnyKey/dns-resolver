#ifndef NETWORK_STREAM_H
#define NETWORK_STREAM_H

#include <cstddef>
#include <cassert>
#include <vector>
#include <cstdint>
#include <string>
#include <algorithm>

#include <boost/type_traits.hpp>

#include <arpa/inet.h>

#include "sassert.hpp"

namespace network {

  struct serializer {

    serializer()
      : buffer_()
    {}

    std::vector<uint8_t> & buffer()
    {
      return buffer_;
    }

    serializer & put(uint8_t n)
    {
      buffer_.push_back(n);
      return *this;
    }

    serializer & operator<<(uint8_t n)
    {
      return put(n);
    }

    serializer & put(uint16_t n)
    {
      n = htons(n);
      return put(uint8_t(n & 0xff)).put(uint8_t(n >> 8));
    }

    serializer & operator<<(uint16_t n)
    {
      return put(n);
    }

    serializer & put(uint32_t n)
    {
      n = htonl(n);
      for(size_t i = 0; i < 4; ++i, n>>=8)
        put(uint8_t(n & 0xff));
      return *this;
    }

    serializer & operator<<(uint32_t n)
    {
      return put(n);
    }

    serializer & put(const std::string & str)
    {
      std::string converted = convert_to_dns_style(str);
      std::copy(converted.begin(), converted.end(), std::back_inserter(buffer_));
      buffer_.push_back(uint8_t()); // not sure
      return *this;
    }

    serializer & operator<<(const std::string & str)
    {
      return put(str);
    }
  
  private:

    inline std::string convert_to_dns_style(std::string dns_query)
    {
      size_t beg = 0;
      size_t occurrence;
      while ((occurrence = dns_query.find_first_of('.', beg)) != std::string::npos) {
        for(size_t i = occurrence; i-- > beg;) {
          dns_query[i+1] = dns_query[i];
        }
        dns_query[beg] = occurrence - beg;
        beg = occurrence + 1;
      }
      occurrence = dns_query.size();
      dns_query.push_back('\0'); // we need to increase size of string, just push any symbol
      for(size_t i = occurrence; i-- > beg;) {
        dns_query[i+1] = dns_query[i];
      }
      dns_query[beg] = occurrence - beg;
    
      return dns_query;
    }


    serializer(const serializer &)             = delete;
    serializer & operator=(const serializer &) = delete;

    std::vector<uint8_t> buffer_;
    
  };

  inline uint16_t network_to_host(uint16_t n)
  {
    return ntohs(n);
  }

  inline uint8_t network_to_host(uint8_t n)
  {
    return n;
  }

  inline uint32_t network_to_host(uint32_t n)
  {
    return ntohl(n);
  }

  struct deserializer {

    deserializer(const std::vector<uint8_t> & buffer, size_t beginning = 0)
      : buffer_(buffer)
      , read_ptr(beginning)
    {}

    template<class Number>
    deserializer & get(Number & n)
    {
      sassert< boost::is_arithmetic<Number>::value > s;
      s = s;
      assert(read_ptr + (sizeof(Number) - 1) < buffer_.size());
      n = *reinterpret_cast<const Number *>(&buffer_[read_ptr]);
      n = network_to_host(n);
      read_ptr += sizeof(Number);
      return *this;
    }

    deserializer & get_raw_str(std::string & str)
    {
      assert(read_ptr < buffer_.size());
      std::string s;
      while((read_ptr < buffer_.size()) && buffer_[read_ptr] != '\0') {
        if (buffer_[read_ptr] < 0xc0) {
          s.push_back(buffer_[read_ptr++]);
          continue;
        }
        
        uint16_t offset;
        {
          deserializer ds(buffer_, read_ptr);
          ds >> offset;
          offset -= 0xc000;
        }
        std::string tmp;
        {
          deserializer ds(buffer_, offset);
          ds.get_raw_str(tmp);
        }
        s.append(tmp);
        read_ptr++; // hack for increment below (must be += 2 and return)
        break;
      }
      str = s;
      read_ptr++;               // move ahead of \0
      return *this;
    }

    deserializer & get(std::string & str)
    {
      std::string s;
      get_raw_str(s);
      str = convert_from_dns_style(s);
      return *this;
    }


    deserializer & operator>>(uint8_t & n)
    {
      return get(n);
    }

    deserializer & operator>>(uint16_t & n)
    {
      return get(n);
    }

    deserializer & operator>>(uint32_t & n)
    {
      return get(n);
    }

    deserializer & operator>>(std::string & str)
    {
      return get(str);
    }
    
  private:

    inline std::string convert_from_dns_style(std::string str)
    {
      size_t idx = 0;
      while (idx < str.size()) {
        size_t cnt = static_cast<uint8_t>(str[idx]);
        for (; cnt > 0; --cnt, ++idx) {
          str[idx] = str[idx + 1];
        }
        str[idx++] = '.';
      }
      if (!str.empty())
        str.erase(str.size() - 1);
      return str;
    }
    
    deserializer(const deserializer &)             = delete;
    deserializer & operator=(const deserializer &) = delete;

    
    const std::vector<uint8_t> & buffer_;
    size_t read_ptr;
  };

  

}

#endif /* NETWORK_STREAM_H */
