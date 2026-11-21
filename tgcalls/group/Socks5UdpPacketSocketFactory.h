#ifndef TGCALLS_SOCKS5_UDP_PACKET_SOCKET_FACTORY_H
#define TGCALLS_SOCKS5_UDP_PACKET_SOCKET_FACTORY_H

#include <memory>

#include "api/packet_socket_factory.h"
#include "rtc_base/proxy_info.h"
#include "rtc_base/socket_factory.h"

namespace tgcalls {

// Delegating PacketSocketFactory that routes UDP sockets through the SAME
// SOCKS5 relay (UDP ASSOCIATE) the tested 1:1 call path uses.
//
// Group calls never create a ReflectorPort, so the 1:1 hook in
// ReflectorPort::CreateReflectorClientSocket cannot cover them. The group
// stack (GroupNetworkManager) builds a plain BasicPortAllocator whose UDP
// sockets come from the PacketSocketFactory handed to the allocator —
// that factory is the hook point. This factory delegates everything to
// the wrapped (Basic) factory, except CreateUdpSocket: when a SOCKS5
// proxy is configured, the created UDP socket is wrapped in the identical
// AsyncSocks5UdpSocket the 1:1 path uses (same class, same relay
// host:port, same credentials), so group media — STUN checks, DTLS,
// SRTP — flows through sgrelay 161.118.196.94:18080 exactly like 1:1
// reflector media. No new mechanism, no new route, no payload rewrite.
//
// Behaviour notes:
//  - TCP sockets pass through unwrapped (the vendored factory ignores a
//    SOCKS5 proxy for TCP anyway); ICE prefers UDP host pairs, so the
//    relayed UDP pair is nominated when it works.
//  - IPv6 UDP sockets are left direct: the relay's UDP endpoint (BND) is
//    IPv4 and an IPv6-bound socket cannot SendTo it. ICE prefers the
//    IPv4 relay pair.
//  - If the wrap fails synchronously (relay unreachable at gather time),
//    the socket is dropped and nullptr is returned, mirroring
//    ReflectorPort's 1:1 behaviour: the allocation-error path runs
//    instead of silently falling back to a direct socket.
class Socks5UdpPacketSocketFactory : public rtc::PacketSocketFactory {
public:
    // Takes ownership of inner. socket_factory is only used inside
    // AsyncSocks5UdpSocket's ctor (to open the TCP ASSOCIATE control
    // connection) and must stay alive as long as this factory.
    Socks5UdpPacketSocketFactory(std::unique_ptr<rtc::PacketSocketFactory> inner,
                                 rtc::SocketFactory* socket_factory,
                                 const rtc::ProxyInfo& proxy);
    ~Socks5UdpPacketSocketFactory() override;

    Socks5UdpPacketSocketFactory(const Socks5UdpPacketSocketFactory&) = delete;
    Socks5UdpPacketSocketFactory& operator=(const Socks5UdpPacketSocketFactory&) = delete;

    rtc::AsyncPacketSocket* CreateUdpSocket(const rtc::SocketAddress& local_address,
                                            uint16_t min_port,
                                            uint16_t max_port) override;
    rtc::AsyncListenSocket* CreateServerTcpSocket(const rtc::SocketAddress& local_address,
                                                  uint16_t min_port,
                                                  uint16_t max_port,
                                                  int opts) override;
    rtc::AsyncPacketSocket* CreateClientTcpSocket(const rtc::SocketAddress& local_address,
                                                  const rtc::SocketAddress& remote_address,
                                                  const rtc::ProxyInfo& proxy_info,
                                                  const std::string& user_agent,
                                                  const rtc::PacketSocketTcpOptions& tcp_options) override;
    std::unique_ptr<webrtc::AsyncDnsResolverInterface> CreateAsyncDnsResolver() override;

private:
    std::unique_ptr<rtc::PacketSocketFactory> inner_;
    rtc::SocketFactory* socket_factory_;  // not owned
    rtc::ProxyInfo proxy_;
};

} // namespace tgcalls

#endif // TGCALLS_SOCKS5_UDP_PACKET_SOCKET_FACTORY_H
