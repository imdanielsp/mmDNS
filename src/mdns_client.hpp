#pragma once

#include <atomic>
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <iostream>
#include <memory>
#include <optional>

#include "detail/mdns_diag.hpp"
#include "lib/dnslib/src/exception.h"
#include "mdns_message.hpp"
#include "mdns_message_codec.hpp"
#include "mdns_service_register.hpp"
namespace mmdns::client {

using namespace boost::asio;

template <typename net_stream>
class mdns_client {
 public:
  mdns_client()
      : in_stream_(),
        io_service_(),
        worker_ctx_(),
        socket_(io_service_),
        socket_strand_(io_service_),
        sender_endpoint_(),
        service_registry_(io_service_),
        signals_(io_service_, SIGINT, SIGTERM) {
    memset(in_stream_, 0, sizeof(in_stream_));
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
  void stop() {
    service_registry_.stop();
    worker_ctx_.stop();
  }

  void register_service(
      service::descriptor&& service,
      const std::optional<
          std::function<void(bool, const service::descriptor&)>>& cb = {}) {
    service_registry_.register_service(std::move(service), cb);
  }

  bool unregister_service(const std::string& service_name) {}

  void on_data(const boost::system::error_code& error, size_t bytes_recvd) {
    if (!error) {
      net_stream stream(in_stream_, bytes_recvd);

      std::shared_ptr<dns::Message> message = std::make_shared<dns::Message>();
      mmdns::codec::mdns_message_codec codec{*message};

      bool decoded = false;

      try {
        decoded = codec.decode(stream);
      } catch (dns::Exception e) {
        diag("Decoder error: " + std::string(e.what()));
      }

      // TODO: Move this code into a responder/dispatcher
      if (decoded) {
        io_service_.post(
            socket_strand_.wrap([this, message = std::move(message)]() {
              if (message->getQr() == 0 && message->getQdCount() > 0) {
                for (const auto& query : message->getQueries()) {
                  auto service_name = query->getName();
                  diag("Looking for " + service_name);

                  auto descriptor =
                      service_registry_.get_service_descriptor(service_name);

                  if (descriptor) {
                    auto message = descriptor.value().get().message;

                    message->setQr(1);
                    size_t encoded_size = sizeof(out_stream_);
                    mmdns::codec::mdns_message_codec codec{*message};
                    bool encoded = codec.encode(out_stream_, encoded_size);

                    if (encoded) {
                      socket_.async_send_to(
                          boost::asio::const_buffer(out_stream_, encoded_size),
                          destination_endpoint,
                          socket_strand_.wrap(
                              [service_name, message](
                                  const boost::system::error_code& ec,
                                  std::size_t bytes_transferred) {
                                if (!ec) {
                                  diag("Sent response for " + service_name +
                                       "\n" + message->asString());
                                }
                              }));
                    }
                  }
                }
              }
            }));
      }
    }

    async_receive();
  }

 private:
  void async_receive() {
    socket_.async_receive_from(
        boost::asio::buffer(in_stream_, sizeof(in_stream_)), sender_endpoint_,
        socket_strand_.wrap([handler = this](boost::system::error_code ec,
                                             std::size_t bytes_recvd) {
          handler->on_data(ec, bytes_recvd);
        }));
  }

  void start_(bool async) {
    ip::udp::endpoint listen_endpoint(local_address, 5353);
    socket_.open(listen_endpoint.protocol());
    socket_.set_option(ip::udp::socket::reuse_address(true));
    socket_.set_option(ip::multicast::join_group(mdns_address));
    socket_.bind(listen_endpoint);

    async_receive();

    worker_ctx_.post([]() {});
    signals_.async_wait(
        [handler = this](const boost::system::error_code& ec, int sig_num) {
          handler->handle_system_signal(ec, sig_num);
        });

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

  void handle_system_signal(const boost::system::error_code& ec, int sig_num) {
    if (!ec) {
      stop();
    }
  };

 private:
  const ip::address local_address = ip::address::from_string("0.0.0.0");
  const ip::address mdns_address = ip::address::from_string("224.0.0.251");
  const size_t mdns_port = 5353;
  const ip::udp::endpoint destination_endpoint =
      ip::udp::endpoint(mdns_address, mdns_port);

  net::net_stream_data in_stream_[1024];
  net::net_stream_data out_stream_[1024];

  boost::asio::io_service io_service_;
  boost::asio::io_context worker_ctx_;
  ip::udp::socket socket_;
  boost::asio::io_service::strand socket_strand_;

  ip::udp::endpoint sender_endpoint_;

  service::registry service_registry_;

  std::array<std::unique_ptr<std::thread>, 4> thread_pool_;
  boost::asio::signal_set signals_;
};

}  // namespace mmdns::client
