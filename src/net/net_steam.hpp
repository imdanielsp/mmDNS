#pragma once
#include <cstdint>

namespace mmdns::net {

using net_stream_data = uint8_t;
using net_stream_pointer = uint8_t const*;

class net_stream {
 public:
  net_stream(net_stream_pointer data, const size_t data_size)
      : data_(data), data_size_(data_size), bytes_read_(0) {}

  ~net_stream() = default;

  std::tuple<bool, net_stream_pointer, net_stream_pointer> read(
      size_t byte_count) {
    if ((data_size_ - bytes_read_) < byte_count) {
      return std::make_tuple(false, nullptr, nullptr);
    }

    bytes_read_ += byte_count;
    auto start = data_;
    data_ += byte_count;
    return std::tuple(true, start, data_);
  }

  std::tuple<bool, net_stream_pointer> seek(size_t offset) {
    if (data_size_ < offset) {
      return std::make_tuple(false, nullptr);
    }

    return std::make_tuple(true, (data_ - bytes_read_) + offset);
  }

  size_t get_size() const { return data_size_; }
  size_t get_bytes_read() const { return bytes_read_; }

 private:
  net_stream_pointer data_;
  const size_t data_size_;
  size_t bytes_read_;
};
}  // namespace mmdns::net
