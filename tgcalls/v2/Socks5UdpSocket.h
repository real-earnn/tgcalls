#ifndef TGCALLS_SOCKS5_UDP_SOCKET_H
#define TGCALLS_SOCKS5_UDP_SOCKET_H

#include <deque>
#include <utility>

#include "rtc_base/async_packet_socket.h"
#include "rtc_base/copy_on_write_buffer.h"
#include "rtc_base/proxy_info.h"
#include "rtc_base/socket.h"
#include "rtc_base/socket_address.h"
#include "rtc_base/socket_factory.h"
#include "v2/Socks5ProxySocket.h"

namespace tgcalls {

// Async SOCKS5 UDP ASSOCIATE packet socket (RFC 1928 section 7).
//
// Wraps a plain UDP AsyncPacketSocket (created by the port allocator's
// factory, bound to the local network like any direct UDP socket) and
// routes its datagrams through a SOCKS5 relay instead of direct to the
// destination:
//
//  - The ctor opens a TCP connection to the relay and runs a UDP ASSOCIATE
//    handshake (greeting -> RFC 1929 auth -> CMD=3) on it, reusing
//    AsyncSocks5ProxySocket. The TCP connection stays open for the life of
//    this socket: the relay tears the association down when it closes.
//  - SendTo(dest, data) wraps the payload in a SOCKS5 UDP header
//    (RSV=0, FRAG=0, ATYP+DST.ADDR+DST.PORT) and sends it to the BND
//    address the relay advertised in the ASSOCIATE reply.
//  - Inbound datagrams arriving from the BND are unwrapped and delivered
//    with source_address() = the header's DST address (the reflector), so
//    the port above sees exactly what a direct UDP socket would show.
//  - Sends issued before the association is up are queued (cap 16, oldest
//    dropped) and flushed on connect — the reflector hello is sent the
//    moment the port is created, before any reply can arrive.
//  - If the association fails, the socket goes STATE_CLOSED and notifies
//    close: the port never becomes READY and ICE falls back to the other
//    relay ports (TCP-via-relay keeps working).
//
// Used by ReflectorPort for UDP reflector ports only, when a SOCKS5 proxy
// is configured. 1:1 calls only: group calls never create a ReflectorPort.
class AsyncSocks5UdpSocket : public rtc::AsyncPacketSocket {
public:
    // Takes ownership of udp_socket. socket_factory is only used in the
    // ctor (to create the TCP control socket); it must be valid then.
    AsyncSocks5UdpSocket(rtc::AsyncPacketSocket* udp_socket,
                         rtc::SocketFactory* socket_factory,
                         const rtc::ProxyInfo& proxy,
                         const rtc::SocketAddress& destination);
    ~AsyncSocks5UdpSocket() override;

    AsyncSocks5UdpSocket(const AsyncSocks5UdpSocket&) = delete;
    AsyncSocks5UdpSocket& operator=(const AsyncSocks5UdpSocket&) = delete;

    int Send(const void* pv, size_t cb, const rtc::PacketOptions& options) override;
    int SendTo(const void* pv, size_t cb, const rtc::SocketAddress& addr, const rtc::PacketOptions& options) override;
    rtc::SocketAddress GetLocalAddress() const override;
    rtc::SocketAddress GetRemoteAddress() const override;
    int Close() override;
    State GetState() const override;
    int GetOption(rtc::Socket::Option opt, int* value) override;
    int SetOption(rtc::Socket::Option opt, int value) override;
    int GetError() const override;
    void SetError(int error) override;

    // The relay UDP endpoint (BND) from the ASSOCIATE reply; valid once
    // GetState() == STATE_CONNECTED. Empty before that.
    rtc::SocketAddress bound_address() const { return bound_; }

private:
    void OnControlConnected(rtc::Socket* socket);
    void OnControlClosed(rtc::Socket* socket, int err);
    void OnUdpPacket(rtc::AsyncPacketSocket* socket, const rtc::ReceivedPacket& packet);
    void OnInnerSentPacket(rtc::AsyncPacketSocket* socket, const rtc::SentPacket& sent_packet);
    void OnInnerReadyToSend(rtc::AsyncPacketSocket* socket);
    void OnInnerAddressReady(rtc::AsyncPacketSocket* socket, const rtc::SocketAddress& address);
    void OnInnerClosed(rtc::AsyncPacketSocket* socket, int err);
    void FlushQueue();
    void Fail(int error);

    rtc::AsyncPacketSocket* udp_;  // owned: the local UDP socket
    AsyncSocks5ProxySocket* control_;  // owned: TCP ASSOCIATE connection (owns its raw socket)
    rtc::SocketAddress destination_;  // reflector address (the UDP target)
    rtc::SocketAddress bound_;  // relay BND address, set on associate success
    State state_ = STATE_CONNECTING;
    int error_ = 0;
    bool destroying_ = false;
    bool first_media_seen_ = false;
    std::deque<std::pair<rtc::SocketAddress, rtc::CopyOnWriteBuffer>> pending_;
};

} // namespace tgcalls

#endif // TGCALLS_SOCKS5_UDP_SOCKET_H
