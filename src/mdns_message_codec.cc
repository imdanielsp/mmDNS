#include "mdns_message_codec.hpp"

#include <boost/range/algorithm.hpp>
#include <string_view>
#include "detail/mdns_diag.hpp"
#include "net/net_steam.hpp"

using namespace mmdns::net;
using namespace mmdns::message;

namespace mmdns::codec {
mdns_message_codec::mdns_message_codec(mdns_message_t& message)
    : message_(message) {}

bool mdns_message_codec::decode(net::net_stream& stream) {
  if (!decode_header_(stream)) {
    diag("Failed to decode mdns header");
    return false;
  }

  if (message_.header.question_count > 0 && !decode_queries_(stream)) {
    diag("Failed to decode mdns queries");
    return false;
  }

  // if (message_.header.answer_count > 0 && !decode_rrs_(stream)) {
  //   diag("Failed to decode mdns queries");
  //   return false;
  // }

  return true;
};

std::vector<uint8_t> mdns_message_codec::encode() {
  std::vector<uint8_t> bytes;
  encode_header_(bytes);
  encode_queries_(bytes);
  encode_answers_(bytes);
  return bytes;
};

namespace {
template <typename Reader, typename Dest>
bool consume_(Reader* reader, net_stream& stream, Dest& dest) {
  assert(reader);

  bool read_status = false;
  net_stream_pointer steam_ptr = nullptr;
  net_stream_pointer _ = nullptr;
  std::tie(read_status, steam_ptr, _) = stream.read(sizeof(dest));

  if (read_status) {
    dest = (*reader)(steam_ptr);
  }

  return read_status;
}

auto defaultNameFormatter =
    [](std::string& output, net_stream_pointer ptr, size_t size) -> bool {
  output.append(reinterpret_cast<const char*>(ptr), size);
  output += '.';
  return true;  // Continue processing if necessary
};

std::string consume_dns_name(
    net_stream& stream,
    std::function<bool(std::string&, net_stream_pointer, size_t)> formatter =
        defaultNameFormatter) {
  std::string output;
  uint8_t label_size = std::numeric_limits<uint8_t>::max();

  bool read_status = false;
  net_stream_pointer ptr = nullptr;
  net_stream_pointer end_ptr = nullptr;
  std::tie(read_status, ptr, end_ptr) = stream.read(sizeof(label_size));
  label_size = read_u8(ptr);
  ptr++;

  if (label_size == 0) {
    return "";
  }

  if (!read_status) {
    diag("Failed to decode DNS name");
    return "";
  }

  do {
    auto src = ptr;

    // Check if the first 2 high order bits are on
    bool is_compressed = ((label_size & 0xC0) >> 6) > 0;
    if (is_compressed) {
      // TODO: Clean this up?
      uint8_t position_second_byte = 0;
      consume_(read_u8, stream, position_second_byte);
      uint16_t position = position_second_byte;
      position |= (label_size & 0x3F) << 8;
      std::tie(read_status, src) = stream.seek(position);

      // Consume the length of the label
      label_size = read_u8(src);
      src++;
    }

    auto should_continue = formatter(output, src, label_size);

    if (is_compressed || !should_continue) {
      break;
    }

    std::tie(read_status, src, end_ptr) = stream.read(label_size);
    ptr += label_size + 1;

    read_status = consume_(read_u8, stream, label_size);
  } while (label_size != 0);

  return output;
}
}  // namespace

bool mdns_message_codec::decode_header_(net::net_stream& stream) {
  auto& header = message_.header;
  uint8_t status = 0;
  status |= consume_(read_u16, stream, header.id) ? 0 : 1;
  status |= consume_(read_u16, stream, header.flags) ? 0 : 1 << 1;
  status |= consume_(read_u16, stream, header.question_count) ? 0 : 1 << 2;
  status |= consume_(read_u16, stream, header.answer_count) ? 0 : 1 << 3;
  status |= consume_(read_u16, stream, header.authority_rr_count) ? 0 : 1 << 4;
  status |= consume_(read_u16, stream, header.additional_rr_count) ? 0 : 1 << 5;

  return status == 0;
}

bool mdns_message_codec::decode_queries_(net::net_stream& stream) {
  assert(message_.header.question_count > 0);

  auto& queries = message_.queries;
  queries.reserve(message_.header.question_count);

  for (size_t idx = 0; idx < message_.header.question_count; idx++) {
    mdns_query_t query;
    bool status = decode_query_(stream, query);
    if (!status) {
      diag("Failed to decode query @ idx: " + std::to_string(idx));
      return status;
    }
    queries.push_back(std::move(query));
  }

  return true;
}

bool mdns_message_codec::decode_query_(net::net_stream& stream,
                                       mdns_query_t& query) {
  query.name = consume_dns_name(stream);

  uint8_t status = 0;
  uint8_t nthBit = 0;
  if (query.name.empty()) {
    status |= 1 << nthBit++;
  }

  status |= consume_(read_u16, stream, query.query_type) ? 0 : 1 << nthBit++;
  status |= consume_(read_u16, stream, query.query_class) ? 0 : 1 << nthBit++;
  query.unicast_response = (query.query_class & 0x8000) != 0;
  query.query_class &= 0x7FFF;

  return status == 0;
}

bool mdns_message_codec::decode_rrs_(net::net_stream& stream) {
  assert(message_.header.answer_count > 0);

  auto& answers = message_.answers;
  answers.reserve(message_.header.answer_count);

  for (size_t idx = 0; idx < message_.header.answer_count; idx++) {
    mdns_rr_t answer;
    answer.name = consume_dns_name(stream);

    consume_(read_u16, stream, reinterpret_cast<uint16_t&>(answer.type));
    consume_(read_u16, stream, answer.rr_class);
    answer.cache_flush = (answer.rr_class & 0x8000) != 0;
    answer.rr_class &= 0x7FFF;
    consume_(read_u32, stream, answer.ttl);
    consume_(read_u16, stream, answer.data_length);

    decode_rr_data_(stream, answer.type, answer.data_length, answer.data);

    answers.push_back(std::move(answer));
  }

  for (size_t idx = 0; idx < message_.header.authority_rr_count; idx++) {
    mdns_rr_t answer;
    answer.name = consume_dns_name(stream);

    consume_(read_u16, stream, reinterpret_cast<uint16_t&>(answer.type));
    consume_(read_u16, stream, answer.rr_class);
    answer.cache_flush = (answer.rr_class & 0x8000) != 0;
    answer.rr_class &= 0x7FFF;
    consume_(read_u32, stream, answer.ttl);
    consume_(read_u16, stream, answer.data_length);

    decode_rr_data_(stream, answer.type, answer.data_length, answer.data);

    answers.push_back(std::move(answer));
  }

  return true;
}

bool mdns_message_codec::decode_rr_data_(net::net_stream& stream,
                                         mdns_rr_type type,
                                         size_t data_size,
                                         mdns_rr_t::data_type& data) {
  bool status = true;
  switch (type) {
    case A:
    case TXT:
      return decode_rr_txt_(stream, data_size, data);
    case SRV: {
      mdns_rr_srv_t rr_srv;
      consume_(read_u16, stream, rr_srv.priority);
      consume_(read_u16, stream, rr_srv.weight);
      consume_(read_u16, stream, rr_srv.port);
      rr_srv.target = consume_dns_name(stream);

      data = rr_srv;
    } break;
    case PTR: {
      mdns_rr_ptr_t rr_ptr;
      rr_ptr.name = consume_dns_name(stream);
      data = rr_ptr;

      status = rr_ptr.name.size() > 0;
    } break;
    default:
      diag("Type: " + rr_type_to_string(type) + "(" + std::to_string(type) +
           +") is NYI\n");
      break;
  }

  return status;
}

bool mdns_message_codec::decode_rr_txt_(net::net_stream& stream,
                                        size_t data_size,
                                        message::mdns_rr_t::data_type& data) {
  auto [status, start_ptr, end_ptr] = stream.read(data_size);

  if (status) {
    mdns_rr_txt_t rr_txt;
    while (start_ptr < end_ptr) {
      auto value_length = read_u8(start_ptr);
      start_ptr++;

      auto mid_ptr = start_ptr;
      auto entry_end_ptr = start_ptr + value_length;
      while (mid_ptr < entry_end_ptr) {
        if (*mid_ptr == '=') {
          break;
        }
        mid_ptr++;
      }

      if (mid_ptr == end_ptr) {
        return false;
      }

      auto key = std::string(reinterpret_cast<const char*>(start_ptr),
                             reinterpret_cast<const char*>(mid_ptr));
      auto value = std::string(reinterpret_cast<const char*>(mid_ptr + 1),
                               reinterpret_cast<const char*>(entry_end_ptr));

      rr_txt.values.push_front(std::make_pair(key, value));
      start_ptr += value_length;
    }
    data = rr_txt;
  }

  return status;
}

void write_8(uint8_t byte, std::vector<uint8_t>& payload) {
  payload.push_back(byte);
}

void write_16(uint16_t bytes, std::vector<uint8_t>& payload) {
  payload.push_back(bytes >> 0x08);
  payload.push_back(bytes & 0xFF);
}

void write_32(uint32_t bytes, std::vector<uint8_t>& payload) {
  payload.push_back(bytes >> 0x18);
  payload.push_back(bytes >> 0x10);
  payload.push_back(bytes >> 0x08);
  payload.push_back(bytes & 0xFF);
}

void write_str(const std::string& str, std::vector<uint8_t>& payload) {
  std::vector<std::string> label_fragments;

  auto start = str.begin();
  for (auto itr = str.begin(); itr != str.end(); itr++) {
    if (*itr == '.') {
      label_fragments.push_back(std::string(start, itr));
      start = itr + 1;
    }
  }

  if (start != str.end()) {
    label_fragments.push_back(std::string(start, str.end()));
  }

  boost::range::for_each(
      label_fragments, [&payload](const auto& label_fragment) {
        write_8(static_cast<uint8_t>(label_fragment.size()), payload);
        boost::range::for_each(label_fragment, [&payload](auto c) {
          write_8(static_cast<uint8_t>(c), payload);
        });
      });
  payload.push_back('\0');
}

bool mdns_message_codec::encode_header_(std::vector<uint8_t>& payload) {
  auto header = message_.header;

  write_16(header.id, payload);
  write_16(header.flags, payload);
  write_16(header.question_count, payload);
  write_16(header.answer_count, payload);
  write_16(header.authority_rr_count, payload);
  write_16(header.additional_rr_count, payload);

  return true;
}

bool mdns_message_codec::encode_queries_(std::vector<uint8_t>& payload) {
  boost::range::for_each(message_.queries,
                         [&payload](const mdns_query_t& query) {
                           write_str(query.name, payload);
                           write_16(query.query_type, payload);
                           uint16_t query_class = query.query_class;
                           query_class |= query.unicast_response ? 0x8000 : 0x0;
                           write_16(query_class, payload);
                         });

  return true;
}

bool mdns_message_codec::encode_answers_(std::vector<uint8_t>& payload) {
  boost::range::for_each(
      message_.answers, [this, &payload](const mdns_rr_t& answer) {
        write_str(answer.name, payload);
        write_16(static_cast<uint16_t>(answer.type), payload);
        uint16_t rr_class = answer.rr_class;
        rr_class |= answer.cache_flush ? 0x8000 : 0x0;
        write_16(rr_class, payload);
        write_32(answer.ttl, payload);
        write_16(answer.data_length, payload);

        encode_data_(payload, answer.type, answer.data);
      });

  boost::range::for_each(
      message_.authorities, [this, &payload](const mdns_rr_t& answer) {
        write_str(answer.name, payload);
        write_16(static_cast<uint16_t>(answer.type), payload);
        uint16_t rr_class = answer.rr_class;
        rr_class |= answer.cache_flush ? 0x8000 : 0x0;
        write_16(rr_class, payload);
        write_32(answer.ttl, payload);
        write_16(answer.data_length, payload);

        encode_data_(payload, answer.type, answer.data);
      });

  return true;
}

bool mdns_message_codec::encode_data_(
    std::vector<uint8_t>& payload,
    message::mdns_rr_type type,
    const message::mdns_rr_t::data_type& data) {
  switch (type) {
    case A:
    case TXT:
      return encode_rr_txt_(payload, std::get<mdns_rr_txt_t>(data));
    case SRV: {
      auto rr_srv = std::get<mdns_rr_srv_t>(data);
      write_16(rr_srv.priority, payload);
      write_16(rr_srv.weight, payload);
      write_16(rr_srv.port, payload);
      write_str(rr_srv.target, payload);
    } break;
    case PTR: {
      auto rr_ptr = std::get<mdns_rr_ptr_t>(data);
      write_str(rr_ptr.name, payload);
    } break;
    default:
      diag("Encoding for type: " + rr_type_to_string(type) + "(" +
           std::to_string(type) + +") is NYI\n");
      break;
  }
  return true;
}

bool mdns_message_codec::encode_rr_txt_(std::vector<uint8_t>& payload,
                                        const message::mdns_rr_txt_t& rr_txt) {
  boost::range::for_each(rr_txt.values, [&payload](const auto& entry) {
    std::string value = entry.first + "=" + entry.second;
    write_8(static_cast<uint8_t>(value.size()), payload);

    boost::range::for_each(value, [&payload](auto c) {
      write_8(static_cast<uint8_t>(c), payload);
    });
  });
  return true;
}
}  // namespace mmdns::codec