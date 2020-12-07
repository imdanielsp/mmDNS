#pragma once

#include <atomic>
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <iostream>
#include <memory>
#include <optional>

#include "detail/mdns_diag.hpp"
#include "mdns_message.hpp"
#include "mdns_message_codec.hpp"
#include "mdns_service_register.hpp"

namespace mmdns::client {

using namespace boost::asio;

template <typename net_stream>
class mdns_client {
 public:
  mdns_client()
      : stream_(),
        io_service_(),
        worker_ctx_(),
        socket_(io_service_),
        sender_endpoint_(),
        service_registry_(worker_ctx_) {
    memset(stream_, 0, sizeof(stream_));
  }

  ~mdns_client() {
    io_service_.stop();

    for (size_t idx = 0; idx < thread_pool_.size(); idx++) {
      if (thread_pool_[idx].get()) {
        assert(thread_pool_[idx]->joinable());
        thread_pool_[idx]->join();
      }
    }

    assert(io_service_.stopped());
  }

  void start() { start_(false); }
  void async_start() { start(true); }

  void register_service(
      service::descriptor&& service,
      const std::optional<
          std::function<void(bool, const service::descriptor&)>>& cb = {}) {
    service_registry_.register_service(std::move(service), cb);
  }

  bool unregister_service(const std::string& service_name) {}

  void on_data(const boost::system::error_code& error, size_t bytes_recvd) {
    if (!error) {
      net_stream stream(stream_, bytes_recvd);

      mmdns::message::mdns_message_t message;
      mmdns::codec::mdns_message_codec codec(message);

      // TODO: Move this code into a responder/dispatcher
      if (codec.decode(stream)) {
        // worker_ctx_.post(mdns_services_strand_.wrap(
        //     [this, message = std::move(message)]() mutable {
        //       bool is_query = (message.header.flags & 0x8000) == 0;
        //       if (is_query && message.header.question_count > 0) {
        //         for (const auto& query : message.queries) {
        //           diag("Looking for " + query.name);
        //           auto itr = mdns_services_.find(query.name);
        //           if (itr != mdns_services_.end()) {
        //             diag("Found " + query.name);
        //             auto service_descriptor = itr->second;
        //             message::mdns_rr_t rr;
        //             rr.name = query.name;
        //             rr.type = message::TXT;
        //             rr.cache_flush = true;
        //             rr.rr_class = query.query_class;
        //             rr.ttl = 3000;
        //             // TODO: Insert the txt from the service_descriptor
        //             message::mdns_rr_txt_t rr_txt;
        //             rr_txt.values.push_back({"test", "daniel"});

        //             rr.data = rr_txt;
        //             rr.data_length = 4 + 1 + 6;
        //             message.answers.push_back(rr);

        //             message.header.answer_count++;
        //             message.header.flags |= 0x8000;

        //             mmdns::codec::mdns_message_codec codec(message);
        //             auto payload = codec.encode();
        //             socket_.async_send_to(
        //                 const_buffer(payload.data(), payload.size()),
        //                 destination_endpoint,
        //                 [](const boost::system::error_code& error,
        //                    std::size_t bytes_transferred) {
        //                   if (!error) {
        //                     diag("Sent " +
        //                     std::to_string(bytes_transferred));
        //                   }
        //                 });
        //           }
        //         }
        //       }
        //     }));
      }
    }

    async_receive();
  }

 private:
  void async_receive() {
    socket_.async_receive_from(boost::asio::buffer(stream_, sizeof(stream_)),
                               sender_endpoint_,
                               [handler = this](boost::system::error_code ec,
                                                std::size_t bytes_recvd) {
                                 handler->on_data(ec, bytes_recvd);
                               });
  }

  void start_(bool async) {
    ip::udp::endpoint listen_endpoint(local_address, 5353);
    socket_.open(listen_endpoint.protocol());
    socket_.set_option(ip::udp::socket::reuse_address(true));
    socket_.set_option(ip::multicast::join_group(mdns_address));
    socket_.bind(listen_endpoint);

    async_receive();
    worker_ctx_.post([]() {});

    for (size_t idx = 0; idx < thread_pool_.max_size() - 1; idx++) {
      thread_pool_[idx] = std::make_unique<std::thread>(
          [client = this]() { client->io_service_.run(); });
    }

    boost::asio::executor_work_guard<decltype(worker_ctx_.get_executor())> work{
        worker_ctx_.get_executor()};
    if (async) {
      thread_pool_[thread_pool_.max_size() - 1] = std::make_unique<std::thread>(
          [client = this]() { client->worker_ctx_.run(); });
    } else {
      worker_ctx_.run();
    }
  }

 private:
  const ip::address local_address = ip::address::from_string("0.0.0.0");
  const ip::address mdns_address = ip::address::from_string("224.0.0.251");
  const size_t mdns_port = 5353;
  const ip::udp::endpoint destination_endpoint =
      ip::udp::endpoint(mdns_address, mdns_port);

  uint8_t stream_[1024];

  boost::asio::io_service io_service_;
  boost::asio::io_context worker_ctx_;
  ip::udp::socket socket_;
  ip::udp::endpoint sender_endpoint_;

  service::registry service_registry_;

  std::array<std::unique_ptr<std::thread>, 4> thread_pool_;
};

}  // namespace mmdns::client
