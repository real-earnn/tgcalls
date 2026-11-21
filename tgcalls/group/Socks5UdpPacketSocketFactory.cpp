#include "group/Socks5UdpPacketSocketFactory.h"

#include <netinet/in.h>
#include <sys/socket.h>

#include "rtc_base/logging.h"
#include "v2/Socks5UdpSocket.h"

namespace tgcalls {

Socks5UdpPacketSocketFactory::Socks5UdpPacketSocketFactory(
    std::unique_ptr<rtc::PacketSocketFactory> inner,
    rtc::SocketFactory* socket_factory,
    const rtc::ProxyInfo& proxy)
    : inner_(std::move(inner)), socket_factory_(socket_factory), proxy_(proxy) {
}

Socks5UdpPacketSocketFactory::~Socks5UdpPacketSocketFactory() {
}

rtc::AsyncPacketSocket* Socks5UdpPacketSocketFactory::CreateUdpSocket(
    const rtc::SocketAddress& local_address, uint16_t min_port, uint16_t max_port) {
    rtc::AsyncPacketSocket* socket = inner_->CreateUdpSocket(local_address, min_port, max_port);
    if (!socket || proxy_.type != rtc::PROXY_SOCKS5) {
        return socket;
    }
    // Only IPv4 sockets: the relay's UDP endpoint (BND) is IPv4, and an
    // IPv6-bound socket cannot SendTo it. IPv6 sockets stay direct; ICE
    // prefers the IPv4 relay pair.
    if (socket->GetLocalAddress().ipaddr().family() == AF_INET6) {
        return socket;
    }
    // No single destination is known at gather time: group calls learn the
    // server from the join payload, after gathering starts. The placeholder
    // only lends its AF_INET family to the ASSOCIATE control socket;
    // AsyncSocks5UdpSocket learns the real destination from the first
    // SendTo (STUN check / hello) and reports it in the SG-UDP markers.
    rtc::AsyncPacketSocket* wrapped = new AsyncSocks5UdpSocket(
        socket, socket_factory_, proxy_,
        rtc::SocketAddress(rtc::IPAddress(INADDR_ANY), 0));
    if (wrapped->GetState() == rtc::AsyncPacketSocket::STATE_CLOSED) {
        RTC_LOG(LS_ERROR) << "Socks5UdpPacketSocketFactory: failed to wrap UDP socket for relay, dropping it";
        delete wrapped;
        return nullptr;
    }
    return wrapped;
}

rtc::AsyncListenSocket* Socks5UdpPacketSocketFactory::CreateServerTcpSocket(
    const rtc::SocketAddress& local_address, uint16_t min_port, uint16_t max_port, int opts) {
    return inner_->CreateServerTcpSocket(local_address, min_port, max_port, opts);
}

rtc::AsyncPacketSocket* Socks5UdpPacketSocketFactory::CreateClientTcpSocket(
    const rtc::SocketAddress& local_address,
    const rtc::SocketAddress& remote_address,
    const rtc::ProxyInfo& proxy_info,
    const std::string& user_agent,
    const rtc::PacketSocketTcpOptions& tcp_options) {
    return inner_->CreateClientTcpSocket(local_address, remote_address, proxy_info, user_agent, tcp_options);
}

std::unique_ptr<webrtc::AsyncDnsResolverInterface> Socks5UdpPacketSocketFactory::CreateAsyncDnsResolver() {
    return inner_->CreateAsyncDnsResolver();
}

} // namespace tgcalls
