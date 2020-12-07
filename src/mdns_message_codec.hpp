#pragma once

#include <cinttypes>
#include <list>
#include <string>

#include "mdns_message.hpp"

namespace mmdns::net {
class net_stream;
}  // namespace mmdns::net

namespace mmdns::codec {

class mdns_message_codec {
 public:
  mdns_message_codec(message::mdns_message_t& message);

  ~mdns_message_codec() = default;

  bool decode(net::net_stream& stream);

  std::vector<uint8_t> encode();

 private:
  bool decode_header_(net::net_stream& stream);
  bool decode_queries_(net::net_stream& stream);
  bool decode_query_(net::net_stream& stream, message::mdns_query_t& query);
  bool decode_rrs_(net::net_stream& stream);
  bool decode_rr_data_(net::net_stream& stream,
                       message::mdns_rr_type type,
                       size_t data_size,
                       message::mdns_rr_t::data_type& data);
  bool decode_rr_txt_(net::net_stream& stream,
                      size_t data_size,
                      message::mdns_rr_t::data_type& data);

  bool encode_header_(std::vector<uint8_t>& payload);
  bool encode_queries_(std::vector<uint8_t>& payload);
  bool encode_answers_(std::vector<uint8_t>& payload);
  bool encode_data_(std::vector<uint8_t>& payload,
                    message::mdns_rr_type type,
                    const message::mdns_rr_t::data_type& data);
  bool encode_rr_txt_(std::vector<uint8_t>& payload,
                      const message::mdns_rr_txt_t& rr_txt);

 private:
  message::mdns_message_t& message_;
};

}  // namespace mmdns::codec
