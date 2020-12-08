#include "mdns_message_codec.hpp"

#include <boost/range/algorithm.hpp>
#include <string_view>
#include "detail/mdns_diag.hpp"
#include "lib/dnslib/src/message.h"

using namespace mmdns::net;

namespace mmdns::codec {
mdns_message_codec::mdns_message_codec(dns::Message& message)
    : message_(message) {}

bool mdns_message_codec::decode(net::net_stream& stream) {
  auto [status, ptr] = stream.seek(0);
  message_.decode(reinterpret_cast<const char*>(ptr), stream.get_size());
  return true;
};

bool mdns_message_codec::encode(net::net_stream_pointer ptr, size_t& ptr_size) {
  dns::uint out_size = 0;
  message_.encode(reinterpret_cast<char*>(ptr), ptr_size, out_size);
  ptr_size = out_size;
  return true;
};

}  // namespace mmdns::codec