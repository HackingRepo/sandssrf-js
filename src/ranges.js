"use strict";
// Address space that must never reach the real network.
//
// These are installed as AnyIP kernel routes inside the sandbox namespace, so the
// KERNEL decides which destinations are internal, by longest-prefix match. No
// userspace classifier runs in that case, and there is no "unrecognised, therefore allowed"
// path that an address either matches a route here and is answered by the mock,
// or it has no route in the namespace at all.
//
// That list comes from the RFC reserved internal ips

const IPV4 = [
  "0.0.0.0/8", // "this network"           RFC 1122
  "10.0.0.0/8", // private                  RFC 1918
  "100.64.0.0/10", // carrier-grade NAT        RFC 6598
  "127.0.0.0/8", // loopback                 RFC 1122
  "169.254.0.0/16", // link-local + metadata    RFC 3927
  "172.16.0.0/12", // private                  RFC 1918
  "192.0.0.0/24", // IETF protocol assignment RFC 6890
  "192.0.2.0/24", // TEST-NET-1               RFC 5737
  "192.31.196.0/24", // AS112-v4                 RFC 7535
  "192.52.193.0/24", // AMT                      RFC 7450
  "192.88.99.0/24", // 6to4 relay anycast       RFC 7526
  "192.168.0.0/16", // private                  RFC 1918
  "192.175.48.0/24", // direct delegation AS112  RFC 7534
  "198.18.0.0/15", // benchmarking             RFC 2544
  "198.51.100.0/24", // TEST-NET-2               RFC 5737
  "203.0.113.0/24", // TEST-NET-3               RFC 5737
  "224.0.0.0/4", // multicast                RFC 5771
  "240.0.0.0/4", // reserved + broadcast     RFC 1112
];

// Those are not standard IANA ips, many missed, so will be here
//
// Example:
//
// Microsoft Azure Wire Server, that ip is public in standard RFC normally, however microsoft used it
// Same Alibab Cloud refuse to use standard 169.254 ip range, and used a custom range, so those will be included
const IPV4_CLOUD = [
  "168.63.129.16/32", // Azure wire server
  "100.100.100.200/32", // Alibaba Cloud metadata
];

// Those is the internal ipv6 ips, list
const IPV6 = [
  "::/128", // unspecified
  "::1/128", // loopback
  "::ffff:0:0/96", // IPv4-mapped
  "::/96", // IPv4-compatible (deprecated)  RFC 4291 2.5.5.1
  "64:ff9b::/96", // NAT64 well-known              RFC 6052
  "64:ff9b:1::/48", // NAT64 local-use               RFC 8215
  "100::/64", // discard-only                  RFC 6666
  "2001::/23", // IETF protocol assignments     RFC 2928
  "2001:db8::/32", // documentation                 RFC 3849
  "2002::/16", // 6to4                          RFC 3056
  "3fff::/20", // documentation                 RFC 9637
  "5f00::/16", // SRv6 SIDs                     RFC 9602
  "fc00::/7", // unique local                  RFC 4193
  "fe80::/10", // link-local                    RFC 4291
  "ff00::/8", // multicast                     RFC 4291
];

// Default ports to mock/simulate, in the sandbox, it can be customized by the operator if they want more
const DEFAULT_PORTS = [
  80,
  443,
  8080,
  8443,
  8000,
  3000,
  5000,
  9000,
  6379,
  3306,
  5432,
  27017,
  9200,
  11211,
  2375,
  2379,
  8500,
];

// Export these constants
module.exports = {
  IPV4,
  IPV4_CLOUD,
  IPV6,
  DEFAULT_PORTS,
  defaultMock: () => [...IPV4, ...IPV4_CLOUD],
  defaultMock6: () => [...IPV6],
};
