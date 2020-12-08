# mmDNS
mDNS Implementation in moderm C++ (WIP)

Note: this implementation is extremely unstable and was used as an excuse to learn about DNS messages and the mDNS specialization. **Just use as a reference.**

## mDNS Service Registration

```
Sent registration
Header:
ID: 0
  fields: [ QR: 1 opCode: 0 ]
  QDcount: 0
  ANcount: 4
  NScount: 0
  ARcount: 2
Answers:
  <<TXT items=2 'ip=127.0.0.1' 'port=76555'
  <<PTR ptrdname=_mdnstest._tcp.local
  <<PTR ptrdname=service1._mdnstest._tcp.local
  <<SRV priority=0 weight=0 port=7623 target=localhost
Additional:
  <<RData A addr=127.0.0.1
  <<RData AAAA addr=3a3a:3100:302e:302e:3100:d706:0100:0000
  ```
  
Independent client listening to mDNS multicast ([Discovery](https://apps.apple.com/us/app/discovery-dns-sd-browser/id1381004916?mt=12) in the App Store):

![Screen Shot 2020-12-07 at 11 29 08 PM](https://user-images.githubusercontent.com/8296645/101440112-03a86a80-38e4-11eb-9907-67f19dbe9b55.png)

## mDNS Responder:

```
Looking for service1._mdnstest._tcp.local
Sent response for service1._mdnstest._tcp.local
Header:
ID: 0
  fields: [ QR: 1 opCode: 0 ]
  QDcount: 0
  ANcount: 4
  NScount: 0
  ARcount: 2
Answers:
  <<TXT items=2 'ip=127.0.0.1' 'port=76555'
  <<PTR ptrdname=_mdnstest._tcp.local
  <<PTR ptrdname=service1._mdnstest._tcp.local
  <<SRV priority=0 weight=0 port=7623 target=localhost
Additional:
  <<RData A addr=127.0.0.1
  <<RData AAAA addr=3a3a:3100:302e:302e:3100:d706:0100:0000
```
