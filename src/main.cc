#include <chrono>
#include <iostream>
#include <thread>
#include "mdns_client.hpp"
#include "net/net_steam.hpp"

using namespace mmdns;
using namespace std::chrono_literals;

int main(int argc, char const* argv[]) {
  client::mdns_client<net::net_stream> client{};
  service::descriptor service{
      "test",
      "_mdnstest._tcp",
      "local",
      7623u,
      {std::make_pair("ip", "127.0.0.1"), std::make_pair("port", "76555")}};
  client.register_service(
      std::move(service),
      [](bool status, const service::descriptor& service_desc) {
        std::cout << "Registered " << service_desc.name << std::endl;
      });
  client.start();
  return 0;
}
