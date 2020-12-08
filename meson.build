project('mmDNS', 'cpp',
    version : '1.0.0',
    license : 'MIT')

boost_dep = dependency('boost', modules : ['system', 'thread'])

src = [
    'src/mdns_message.cc',
    'src/mdns_message_codec.cc',
    'src/detail/mdns_diag.cc'
]

dns_decoder_src = [
    'lib/dnslib/src/buffer.cpp',
    'lib/dnslib/src/message.cpp',
    'lib/dnslib/src/qs.cpp',
    'lib/dnslib/src/rr.cpp'
]

exe = executable('mmdnsd',
                 ['src/main.cc', dns_decoder_src, src],
                 cpp_args : '-std=c++2a',
                 dependencies : boost_dep)

gtest_dep = dependency('gtest', main : true, required : true)
gmock_dep = dependency('gmock', main : true, required : true)

tests_src = [
  'tests/test_main.cc'
]

test_exec = executable('mmdnsd_test', 
                       [src, dns_decoder_src, tests_src],
                       cpp_args : '-std=c++17',
                       dependencies: [
                           gtest_dep,
                           gmock_dep
                       ])
