#include <chrono>
#include <iostream>
#include <thread>
#include "mdns_client.hpp"
#include "net/net_steam.hpp"

using namespace mmdns;
using namespace std::chrono_literals;

int main(int argc, char const* argv[]) {
  client::mdns_client<net::net_stream> client{};
  service::descriptor service1{
      "service1",
      "localhost",
      "_mdnstest._tcp",
      "local",
      7623u,
      {std::make_pair("ip", "127.0.0.1"), std::make_pair("port", "76555")}};

  service::descriptor service2{
      "service2",
      "localhost",
      "_mdnstest._tcp",
      "local",
      7623u,
      {std::make_pair("ip", "127.0.0.1"), std::make_pair("port", "76555")}};

  client.register_service(std::move(service1));
  client.register_service(std::move(service2));

  client.start();
  return 0;
}
