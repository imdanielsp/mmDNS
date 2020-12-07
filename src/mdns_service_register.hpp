#pragma once

#include <unistd.h>
#include <boost/asio.hpp>
#include <chrono>
#include <cinttypes>
#include <map>
#include <string>

using namespace std::chrono_literals;

namespace mmdns::service {

struct descriptor {
  std::string name;
  std::string type;
  std::string domain;
  uint16_t port;
  std::vector<std::pair<std::string, std::string>> data;
};

class registry {
 public:
  registry(boost::asio::io_context& worker_ctx)
      : worker_ctx_(worker_ctx),
        registry_strand_(worker_ctx_),
        socket_(worker_ctx_),
        service_descriptors_() {}
  ~registry() = default;

  void register_service(
      service::descriptor&& service,
      const std::optional<
          std::function<void(bool, const service::descriptor&)>>& cb = {}) {
    worker_ctx_.post(registry_strand_.wrap([this, service = std::move(service),
                                            cb = std::move(cb)]() {
      mmdns::message::mdns_message_t message;
      build_mdns_message_from_descriptor_(service, message);
      mmdns::codec::mdns_message_codec codec{message};
      auto payload = codec.encode();

      socket_.open(dst_endpoint_.protocol());

      // TODO: Probing
      // TODO Retransmittion
      socket_.async_send_to(
          boost::asio::const_buffer(payload.data(), payload.size()),
          dst_endpoint_,
          registry_strand_.wrap(
              [this, payload = std::move(payload), service = std::move(service),
               cb = std::move(cb)](const boost::system::error_code& error,
                                   std::size_t bytes_transferred) {
                if (!error) {
                  diag("Sent registration of " + service.name);
                  auto [itr, op_result] = service_descriptors_.try_emplace(
                      service.name, std::move(service));
                  if (cb) {
                    cb.value()(op_result, itr->second);
                  }
                }
              }));
    }));
  }

 private:
  bool build_mdns_message_from_descriptor_(const descriptor& descriptor,
                                           message::mdns_message_t& message) {
    message.header.set_query(false);
    message.header.set_op_code(0x0);  // Standard Query (0)
    message.header.set_authorative(true);
    message.header.set_truncated(false);
    message.header.set_response_code(0x0);  // NOERROR (0)

    message::mdns_rr_t txt_rr;
    message::mdns_rr_txt_t rr_txt;
    txt_rr.name = descriptor.type + "." + descriptor.domain;
    txt_rr.type = message::TXT;
    txt_rr.cache_flush = false;
    txt_rr.rr_class = 0x01;
    txt_rr.ttl = 4500;

    size_t data_length = 0;
    for (auto data : descriptor.data) {
      data_length += data.first.size() + data.second.size() + 1;
      rr_txt.values.push_front(data);
    }
    txt_rr.data_length = data_length;
    txt_rr.data = rr_txt;
    message.answers.push_back(txt_rr);

    // At least three records will be addded: 2 PTR and 1 SRV -- TXT are
    // optional
    message::mdns_rr_t pointer_rr;
    message::mdns_rr_ptr_t rr_ptr;
    pointer_rr.name = descriptor.type + "." + descriptor.domain;
    pointer_rr.type = message::PTR;
    pointer_rr.cache_flush = false;
    pointer_rr.rr_class = 0x01;
    pointer_rr.ttl = 4500;
    rr_ptr.name = descriptor.type + "." + descriptor.domain;
    pointer_rr.data_length = rr_ptr.name.size();
    pointer_rr.data = rr_ptr;
    message.answers.push_back(std::move(pointer_rr));

    message::mdns_rr_t service_rr;
    message::mdns_rr_srv_t rr_srv;
    service_rr.name =
        descriptor.name + "." + descriptor.type + "." + descriptor.domain;
    service_rr.type = message::SRV;
    service_rr.cache_flush = true;
    service_rr.rr_class = 0x01;
    service_rr.ttl = 120;
    rr_srv.priority = 0;
    rr_srv.weight = 0;
    rr_srv.port = descriptor.port;

    char host_name[256];
    gethostname(host_name, sizeof(host_name));
    rr_srv.target = host_name;
    rr_srv.target.append(".local");

    service_rr.data_length = rr_srv.get_size();
    service_rr.data = rr_srv;
    message.answers.push_back(std::move(service_rr));

    message.header.answer_count = message.answers.size();
  }

 private:
  boost::asio::io_service& worker_ctx_;
  boost::asio::io_service::strand registry_strand_;

  boost::asio::ip::udp::socket socket_;

  // TODO: Get this IPv4 dynamically from the system
  const boost::asio::ip::address dns_srv_address_ =
      boost::asio::ip::address::from_string("224.0.0.251");
  const size_t dns_port = 5353;
  const boost::asio::ip::udp::endpoint dst_endpoint_ =
      boost::asio::ip::udp::endpoint(dns_srv_address_, dns_port);

  std::map<std::string, descriptor> service_descriptors_;
};

}  // namespace mmdns::service