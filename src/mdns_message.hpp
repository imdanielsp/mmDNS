#pragma once

#include <cstdint>
#include <forward_list>
#include <iomanip>
#include <ostream>
#include <string>
#include <variant>
#include <vector>
#include "detail/config.hpp"

#include <boost/range/algorithm.hpp>

namespace mmdns::message {

constexpr uint16_t read_u8(const uint8_t* MMDNS_NON_NULL ptr) {
  return ptr[0];
}

constexpr uint16_t read_u16(const uint8_t* MMDNS_NON_NULL ptr) {
  return ((ptr[0] & 0xFF) << 8) | ((ptr[1] & 0xFF) << 0);
}

constexpr uint32_t read_u32(const uint8_t* MMDNS_NON_NULL ptr) {
  return ((ptr[0] & 0xFF) << 24) | ((ptr[1] & 0xFF) << 16) |
         ((ptr[2] & 0xFF) << 8) | ((ptr[3] & 0xFF) << 0);
}

#define consume(count, from, to)       \
  do {                                 \
    (to) = read_u##count((from));      \
    (from) += sizeof(uint##count##_t); \
  } while (0)

// Implement name uncompresion as described in
// https://tools.ietf.org/html/rfc883#page-31
std::pair<std::string, size_t> comsume_dns_name(uint8_t* stream, size_t offset);

struct mdns_header_t {
  static constexpr auto QUERY_MASK = 0x8000;
  static constexpr auto OPCODE_MASK = 0x7800;
  static constexpr auto AUTHORATIVE_MASK = 0x400;
  static constexpr auto TRUNCATED_MASK = 0x200;
  static constexpr auto RESPONSE_CODE_MASK = 0x0F;

  uint16_t id;
  uint16_t flags;
  uint16_t question_count;
  uint16_t answer_count;
  uint16_t authority_rr_count;
  uint16_t additional_rr_count;

  bool is_query() const { return (flags & QUERY_MASK) == 0; }
  void set_query(bool is_query) { flags |= is_query ? QUERY_MASK : 0; }

  uint8_t op_code() const { return (flags & OPCODE_MASK) >> 11; }
  void set_op_code(uint8_t op_code) { flags |= (flags & op_code) << 11; }

  bool has_authorative() const { return (flags & AUTHORATIVE_MASK) != 0; }
  void set_authorative(bool is_authorative) {
    flags |= is_authorative ? AUTHORATIVE_MASK : 0;
  }

  bool is_truncated() const { return (flags & TRUNCATED_MASK) != 0; }
  void set_truncated(bool is_truncated) {
    flags |= is_truncated ? TRUNCATED_MASK : 0;
  }

  uint8_t response_code() const { return (flags & RESPONSE_CODE_MASK); }
  void set_response_code(uint8_t resp_code) { flags |= resp_code; }

  void dump(std::ostream& sout) const {
    sout << "------------- Header -----------------" << std::endl;
    sout << "| id: " << id << std::endl;
    sout << "| flags: " << flags << std::endl;
    // TODO: Use functions or macros to extrac these bits
    sout << "|  q/r: " << ((flags & 0x8000) == 0 ? "q" : "r") << std::endl;
    sout << "|  op: " << (11 >> (flags & 0x7800)) << std::endl;
    sout << "|  aa: " << ((flags & 0x400) > 0) << std::endl;
    sout << "|  tc: " << ((flags & 0x200) > 0) << std::endl;
    sout << "|  rd: " << ((flags & 0x100) > 0) << std::endl;
    sout << "|  ra: " << ((flags & 0x80) > 0) << std::endl;
    sout << "|  rcode: " << (flags & 0xF) << std::endl;
    sout << "| query count: " << question_count << std::endl;
    sout << "| answer count: " << answer_count << std::endl;
    sout << "| authority count: " << authority_rr_count << std::endl;
    sout << "| additional count: " << additional_rr_count << std::endl;
  }
};

struct mdns_query_t {
  std::string name;  // Variable name, cap it at 256
  uint16_t query_type;
  bool unicast_response;
  uint16_t query_class;

  void dump(std::ostream& sout) const {
    sout << "| name: " << name << std::endl;
    sout << "| query_type: " << query_type << std::endl;
    sout << "| unicast_response: " << unicast_response << std::endl;
    sout << "| query_class: " << query_class << std::endl;
  }
};

enum mdns_rr_type : uint16_t {
  A = 1,       // a ip4v host address
  NS = 2,      // an authoritative name server
  MD = 3,      // a mail destination (Obsolete - use MX)
  MF = 4,      // a mail forwarder (Obsolete - use MX)
  CNAME = 5,   // the canonical name for an alias
  SOA = 6,     // marks the start of a zone of authority
  MB = 7,      // a mailbox domain name (EXPERIMENTAL)
  MG = 8,      // a mail group member (EXPERIMENTAL)
  MR = 9,      // a mail rename domain name (EXPERIMENTAL)
  NULL_ = 10,  // a null RR (EXPERIMENTAL)
  WKS = 11,    // a well known service description
  PTR = 12,    // a domain name pointer
  HINFO = 13,  // host information
  MINFO = 14,  // mailbox or mail list information
  MX = 15,     // mail exchange
  TXT = 16,    // text strings
  AAAA = 28,   // a ip6v host address
  SRV = 33,    // Generalized service location record
  ANY = 255
};

std::string rr_type_to_string(mdns_rr_type type);

struct mdns_rr_a_t {};

struct mdns_rr_txt_t {
  using key_type = std::string;
  using value_type = std::string;

  std::forward_list<std::pair<key_type, value_type>> values;
};

struct mdns_rr_srv_t {
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
  std::string target;

  size_t get_size() const {
    return sizeof(priority) + sizeof(weight) + sizeof(port) + target.size();
  }

  void dump(std::ostream& sout) const {
    sout << "| priority: " << priority << std::endl;
    sout << "| weight: " << weight << std::endl;
    sout << "| port: " << port << std::endl;
    sout << "| target: " << target << std::endl;
  }
};

struct mdns_rr_ptr_t {
  std::string name;
};

struct mdns_rr_t {
  std::string name;
  mdns_rr_type type;
  bool cache_flush;
  uint16_t rr_class;
  uint32_t ttl;
  uint16_t data_length;

  using data_type =
      std::variant<mdns_rr_a_t, mdns_rr_txt_t, mdns_rr_srv_t, mdns_rr_ptr_t>;

  data_type data;

  void dump(std::ostream& sout) const {
    sout << "| name: " << name << std::endl;
    sout << "| type: " << rr_type_to_string(type) << std::endl;
    sout << "| cache_flush: " << cache_flush << std::endl;
    sout << "| class: " << rr_class << std::endl;
    sout << "| ttl: " << ttl << std::endl;
    sout << "| data_length: " << data_length << std::endl;

    sout << "| * * * * * * * * " << rr_type_to_string(type)
         << " * * * * * * * *|" << std::endl;

    switch (type) {
      case PTR: {
        mdns_rr_ptr_t rr_ptr = std::get<mdns_rr_ptr_t>(data);
        sout << "| name: " << rr_ptr.name << std::endl;
      } break;
      case TXT: {
        mdns_rr_txt_t rr_txt = std::get<mdns_rr_txt_t>(data);
        boost::range::for_each(rr_txt.values, [&sout](const auto& pair) {
          sout << "|  " << pair.first << " = " << pair.second << std::endl;
        });
      } break;
      case SRV: {
        auto rr_srv = std::get<mdns_rr_srv_t>(data);
        rr_srv.dump(sout);
      } break;
      default:
        break;
    }
  }
};

struct mdns_message_t {
  mdns_header_t header;

  std::vector<mdns_query_t> queries;
  std::vector<mdns_rr_t> answers;
  std::vector<mdns_rr_t> authorities;
  std::vector<mdns_rr_t> additionals;

  void dump(std::ostream& sout) {
    header.dump(sout);
    for (const auto& q : queries) {
      sout << "----------------- Q  -----------------" << std::endl;
      q.dump(sout);
    }

    for (const auto& rr : answers) {
      sout << "----------------- RR -----------------" << std::endl;
      rr.dump(sout);
    }
    sout << "--------------------------------------" << std::endl;
  }
};
}  // namespace mmdns::message
