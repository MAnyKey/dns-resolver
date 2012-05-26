#include <string>
#include <iostream>
#include <sstream>

#include <boost/program_options.hpp>

#include "resolver.hpp"

namespace po = boost::program_options;

std::string format_ip(const std::vector<uint8_t> & ip)
{
  std::ostringstream stream;
  for (size_t i = 0; i < ip.size(); ++i) {
    if (i)
      stream << '.';
    stream << (int)ip[i];
  }
  return stream.str();
}

int main(int argc, char *argv[])
{
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h",     "produce help message")
    ("hostname",   po::value<std::string>(), "host to resolve")
    ("nameserver", po::value<std::string>(), "user provided nameserver (if not provided /etc/resolv.conf will be used)")
    ;
  
  po::positional_options_description p;
  p.add("hostname", 1);

  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
  po::notify(vm);

  if (vm.count("help")) {
    std::cout << desc << std::endl;
    return EXIT_SUCCESS;
  }
  dns::resolver resolver;
  if (vm.count("nameserver"))
    resolver.set_nameserver(vm["nameserver"].as<std::string>());

  if (!vm.count("hostname")) {
    std::cerr << "Hostname not provided.\n";
    std::cerr << desc << std::endl;
    return EXIT_FAILURE;
  }

  std::string hostname = vm["hostname"].as<std::string>();
  dns::hostent h = resolver.gethostbyname(hostname);
  std::cout << "Hostname " << h.name << " has:\n";
  for (const auto & alias : h.aliases) {
    std::cout << "alias:\t" << alias << std::endl;
  }
  for (const auto & ip : h.addresses) {
    std::cout << "IPv4 address:\t" << format_ip(ip) << std::endl;
  }
  return 0;
}
