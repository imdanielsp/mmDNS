#pragma once

#include <netdb.h>
#include <unistd.h>
#include <algorithm>
#include <boost/asio.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <chrono>
#include <cinttypes>
#include <map>
#include <random>
#include <string>

#include "../tests/test_data.hpp"
#include "lib/dnslib/src/message.h"

using namespace std::chrono_literals;

namespace mmdns::service {

struct descriptor {
  std::string name;
  std::string host_name;
  std::string type;
  std::string domain;
  uint16_t port;
  std::vector<std::pair<std::string, std::string>> data;
  std::shared_ptr<dns::Message> message;
};

class registry {
 public:
  registry(boost::asio::io_context& worker_ctx)
      : data_(),
        worker_ctx_(worker_ctx),
        registry_strand_(worker_ctx_),
        socket_(worker_ctx_),
        timer_(worker_ctx_),
        service_descriptors_() {
    socket_.open(dst_endpoint_.protocol());
  }
  ~registry() { stop(); }

  void stop() {
    net::net_stream_data data_[1024];
    auto expire_rr = [](dns::ResourceRecord* rr) { rr->setTtl(0); };

    for (const auto& [key, service_descriptor] : service_descriptors_) {
      auto message = service_descriptor.message;
      message->setQr(1);
      auto answers = message->getAnswers();
      std::for_each(answers.begin(), answers.end(), expire_rr);

      auto authorities = message->getAuthorities();
      std::for_each(authorities.begin(), authorities.end(), expire_rr);

      auto additionals = message->getAdditional();
      std::for_each(additionals.begin(), additionals.end(), expire_rr);

      mmdns::codec::mdns_message_codec codec{*message};

      size_t data_size = sizeof(data_);
      auto encoded = codec.encode(data_, data_size);

      if (encoded) {
        socket_.send_to(boost::asio::const_buffer(data_, data_size),
                        dst_endpoint_);
      }
    }
  }

  void register_service(
      service::descriptor&& service,
      const std::optional<
          std::function<void(bool, const service::descriptor&)>>& cb = {}) {
    worker_ctx_.post(registry_strand_.wrap(
        [this, service = std::move(service), cb = std::move(cb)]() mutable {
          auto message = std::make_shared<dns::Message>();
          service.message = message;
          build_mdns_message_from_descriptor_(service, message);

          mmdns::codec::mdns_message_codec codec{*message};

          size_t data_size = sizeof(data_);
          auto status = codec.encode(data_, data_size);

          std::random_device rd;
          std::mt19937 gen(rd());
          std::uniform_int_distribution<> distrib(100, 250);

          if (status) {
            // TODO: Probing
            for (int retry_count = 0; retry_count < retransmission_count;
                 retry_count++) {
              socket_.send_to(boost::asio::const_buffer(data_, data_size),
                              dst_endpoint_);

              timer_.expires_from_now(
                  boost::posix_time::milliseconds(distrib(gen)));
              timer_.wait();
            }

            diag("Sent registration:\n" + service.message->asString());
            auto [itr, op_result] = insert_service_(std::move(service));
            if (cb) {
              cb.value()(op_result, itr->second);
            }
          }
        }));
  }

  std::optional<std::reference_wrapper<descriptor>> get_service_descriptor(
      const std::string& service_name) {
    std::optional<std::reference_wrapper<descriptor>> service_descriptor = {};
    auto itr = service_descriptors_.find(service_name);
    if (itr != service_descriptors_.end()) {
      service_descriptor = itr->second;
    }
    return service_descriptor;
  }

 private:
  std::pair<std::map<std::string, descriptor>::const_iterator, bool>
  insert_service_(descriptor&& service) {
    std::pair<decltype(service_descriptors_)::const_iterator, bool> result;
    auto msg = service.message;
    for (auto answer : service.message->getAnswers()) {
      result = service_descriptors_.try_emplace(answer->getName(), service);
    }

    for (auto authority : service.message->getAuthorities()) {
      result = service_descriptors_.try_emplace(authority->getName(), service);
    }

    for (auto additional : service.message->getAdditional()) {
      result = service_descriptors_.try_emplace(additional->getName(), service);
    }

    return result;
  }

  bool build_mdns_message_from_descriptor_(
      const descriptor& descriptor,
      std::shared_ptr<dns::Message> message) {
    message->setQr(1);
    message->setAA(1);

    auto txt_rr = new dns::ResourceRecord;
    txt_rr->setName(descriptor.name + "." + descriptor.type + "." +
                    descriptor.domain);
    txt_rr->setType(dns::RDATA_TXT);
    txt_rr->setClass(dns::CLASS_IN_FLUSH);
    txt_rr->setTtl(4500);

    auto txt_data = new dns::RDataTXT;
    for (auto data : descriptor.data) {
      txt_data->addTxt(data.first + "=" + data.second);
    }
    txt_rr->setRData(txt_data);
    message->addAnswer(txt_rr);

    auto service_ptr_rr = new dns::ResourceRecord;
    service_ptr_rr->setName("_services.dns-sd._upd.local");
    service_ptr_rr->setType(dns::RDATA_PTR);
    service_ptr_rr->setClass(dns::CLASS_IN);
    service_ptr_rr->setTtl(4500);

    auto service_ptr_data = new dns::RDataPTR;
    service_ptr_data->setName(descriptor.type + "." + descriptor.domain);
    service_ptr_rr->setRData(service_ptr_data);
    message->addAnswer(service_ptr_rr);

    // At least three records will be addded: 2 PTR and 1 SRV -- TXT are
    // optional
    auto ptr_rr = new dns::ResourceRecord;
    ptr_rr->setName(descriptor.type + "." + descriptor.domain);
    ptr_rr->setType(dns::RDATA_PTR);
    ptr_rr->setClass(dns::CLASS_IN);
    ptr_rr->setTtl(4500);

    auto ptr_data = new dns::RDataPTR;
    ptr_data->setName(descriptor.name + "." + descriptor.type + "." +
                      descriptor.domain);

    ptr_rr->setRData(ptr_data);
    message->addAnswer(ptr_rr);

    auto srv_rr = new dns::ResourceRecord;
    srv_rr->setName(descriptor.name + "." + descriptor.type + "." +
                    descriptor.domain);
    srv_rr->setType(dns::RDATA_SRV);
    srv_rr->setClass(dns::CLASS_IN_FLUSH);
    srv_rr->setTtl(120);

    auto srv_data = new dns::RDataSRV;
    srv_data->setPort(descriptor.port);
    srv_data->setTarget(descriptor.host_name);

    srv_rr->setRData(srv_data);
    message->addAnswer(srv_rr);

    auto a_rr = new dns::ResourceRecord;
    a_rr->setName(descriptor.host_name);
    a_rr->setType(dns::RDATA_A);
    a_rr->setClass(dns::CLASS_IN_FLUSH);
    a_rr->setTtl(120);

    auto a_data = new dns::RDataA;
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(decltype(hints)));
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_INET;
    auto n =
        getaddrinfo(descriptor.host_name.c_str(), nullptr, &hints, &result);

    if (n != 0) {
      diag("Failed to get host ipv4 address");
      return false;
    }

    char ip_buffer[128];
    inet_ntop(
        hints.ai_family,
        &(reinterpret_cast<struct sockaddr_in*>(result->ai_addr)->sin_addr),
        ip_buffer, sizeof(ip_buffer));

    a_data->setAddress(ip_buffer);
    a_rr->setRData(a_data);
    message->addAdditional(a_rr);
    freeaddrinfo(result);
    result = nullptr;

    auto aaaa_rr = new dns::ResourceRecord;
    aaaa_rr->setName(descriptor.host_name);
    aaaa_rr->setType(dns::RDATA_AAAA);
    aaaa_rr->setClass(dns::CLASS_IN_FLUSH);
    aaaa_rr->setTtl(120);

    auto aaaa_data = new dns::RDataAAAA;
    hints.ai_family = AF_INET6;
    n = getaddrinfo(descriptor.host_name.c_str(), nullptr, &hints, &result);

    if (n != 0) {
      diag("Failed to get host ipv4 address");
      return false;
    }

    inet_ntop(
        hints.ai_family,
        &(reinterpret_cast<struct sockaddr_in6*>(result->ai_addr)->sin6_addr),
        ip_buffer, sizeof(ip_buffer));
    aaaa_data->setAddress(reinterpret_cast<const unsigned char*>(ip_buffer));
    aaaa_rr->setRData(aaaa_data);
    message->addAdditional(aaaa_rr);

    freeaddrinfo(result);
    return true;
  }

 private:
  net::net_stream_data data_[1024];
  boost::asio::io_service& worker_ctx_;
  boost::asio::io_service::strand registry_strand_;

  boost::asio::ip::udp::socket socket_;
  boost::asio::deadline_timer timer_;
  std::map<size_t, size_t> retransmit_count_;

  const boost::asio::ip::address dns_srv_address_ =
      boost::asio::ip::address::from_string("224.0.0.251");
  const size_t dns_port = 5353;
  const boost::asio::ip::udp::endpoint dst_endpoint_ =
      boost::asio::ip::udp::endpoint(dns_srv_address_, dns_port);
  const size_t retransmission_count = 2;

  std::map<std::string, descriptor> service_descriptors_;
};

}  // namespace mmdns::service