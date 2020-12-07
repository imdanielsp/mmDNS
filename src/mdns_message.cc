#include "mdns_message.hpp"

namespace mmdns::message {

std::string rr_type_to_string(mdns_rr_type type) {
  switch (type) {
    case A:
      return "A";
    case CNAME:
      return "CNAME";
    case PTR:
      return "PTR";
    case TXT:
      return "TXT";
    case AAAA:
      return "AAAA";
    case SRV:
      return "SRV";
    case ANY:
      return "ANY";
  }
  return "Unkwon";
}

}  // namespace mmdns::message
