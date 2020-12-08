#pragma once

#include <cstdint>

#include "net/net_steam.hpp"

namespace dns {
class Message;
}

namespace mmdns::codec {

class mdns_message_codec {
 public:
  mdns_message_codec(dns::Message& message);

  ~mdns_message_codec() = default;

  bool decode(net::net_stream& stream);

  bool encode(net::net_stream_pointer ptr, size_t& ptr_size);

 private:
  dns::Message& message_;
};

}  // namespace mmdns::codec
