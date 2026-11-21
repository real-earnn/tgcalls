#include "v2/Socks5UdpSocket.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <sys/socket.h>

#include <netinet/in.h>

#include "rtc_base/byte_order.h"
#include "rtc_base/logging.h"

namespace tgcalls {

namespace {

// Sends issued before the UDP ASSOCIATE completes are queued; the reflector
// hello is sent the moment the port is created, and it is retransmitted
// every 500ms until the reflector answers, so a small cap is plenty.
constexpr size_t kMaxQueuedPackets = 16;

// Builds a SOCKS5 UDP header (RSV=0, FRAG=0, ATYP+DST.ADDR+DST.PORT) for
// dest into out. Returns false if the destination cannot be represented.
bool AppendUdpHeader(rtc::CopyOnWriteBuffer* out, const rtc::SocketAddress& dest) {
    const uint8_t reserved[3] = {0, 0, 0};
    out->AppendData(reserved, 3);
    if (!dest.hostname().empty() && dest.ipaddr().IsNil()) {
        if (dest.hostname().size() > 255) {
            return false;
        }
        const uint8_t atyp = 0x03;
        out->AppendData(&atyp, 1);
        const uint8_t len = static_cast<uint8_t>(dest.hostname().size());
        out->AppendData(&len, 1);
        out->AppendData(reinterpret_cast<const uint8_t*>(dest.hostname().data()),
                        dest.hostname().size());
    } else if (dest.ipaddr().family() == AF_INET) {
        const uint8_t atyp = 0x01;
        out->AppendData(&atyp, 1);
        in_addr v4 = dest.ipaddr().ipv4_address();
        out->AppendData(reinterpret_cast<const uint8_t*>(&v4.s_addr), 4);
    } else if (dest.ipaddr().family() == AF_INET6) {
        const uint8_t atyp = 0x04;
        out->AppendData(&atyp, 1);
        in6_addr v6 = dest.ipaddr().ipv6_address();
        out->AppendData(reinterpret_cast<const uint8_t*>(&v6.s6_addr), 16);
    } else {
        return false;
    }
    uint16_t port = rtc::HostToNetwork16(static_cast<uint16_t>(dest.port()));
    out->AppendData(reinterpret_cast<const uint8_t*>(&port), 2);
    return true;
}

// Parses a SOCKS5 UDP header. On success returns true, fills dest with the
// header's DST address and payload_offset with the payload start.
bool ParseUdpHeader(const uint8_t* data, size_t size, rtc::SocketAddress* dest, size_t* payload_offset) {
    // Minimum: RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2).
    if (size < 10 || data[0] != 0 || data[1] != 0 || data[2] != 0) {
        return false;
    }
    uint8_t atyp = data[3];
    size_t off = 4;
    if (atyp == 0x01) {
        if (size < off + 4 + 2) {
            return false;
        }
        in_addr v4;
        memcpy(&v4.s_addr, data + off, 4);
        off += 4;
        uint16_t port = static_cast<uint16_t>((data[off] << 8) | data[off + 1]);
        off += 2;
        *dest = rtc::SocketAddress(rtc::IPAddress(v4), port);
    } else if (atyp == 0x04) {
        if (size < off + 16 + 2) {
            return false;
        }
        in6_addr v6;
        memcpy(&v6.s6_addr, data + off, 16);
        off += 16;
        uint16_t port = static_cast<uint16_t>((data[off] << 8) | data[off + 1]);
        off += 2;
        *dest = rtc::SocketAddress(rtc::IPAddress(v6), port);
    } else if (atyp == 0x03) {
        if (size < off + 1) {
            return false;
        }
        uint8_t len = data[off++];
        if (size < off + len + 2) {
            return false;
        }
        std::string host(reinterpret_cast<const char*>(data + off), len);
        off += len;
        uint16_t port = static_cast<uint16_t>((data[off] << 8) | data[off + 1]);
        off += 2;
        *dest = rtc::SocketAddress(host, port);
    } else {
        return false;
    }
    *payload_offset = off;
    return true;
}

} // namespace

AsyncSocks5UdpSocket::AsyncSocks5UdpSocket(rtc::AsyncPacketSocket* udp_socket,
                                           rtc::SocketFactory* socket_factory,
                                           const rtc::ProxyInfo& proxy,
                                           const rtc::SocketAddress& destination)
    : udp_(udp_socket), control_(nullptr), destination_(destination), state_(STATE_CONNECTING) {
    RTC_LOG(LS_INFO) << "AsyncSocks5UdpSocket: UDP ASSOCIATE via "
                     << proxy.address.ToSensitiveString() << " for "
                     << destination_.ToSensitiveString();
    if (!udp_) {
        RTC_LOG(LS_ERROR) << "AsyncSocks5UdpSocket: null UDP socket";
        Fail(EINVAL);
        return;
    }
    udp_->RegisterReceivedPacketCallback([this](rtc::AsyncPacketSocket* socket, const rtc::ReceivedPacket& packet) {
        OnUdpPacket(socket, packet);
    });
    udp_->SignalSentPacket.connect(this, &AsyncSocks5UdpSocket::OnInnerSentPacket);
    udp_->SignalReadyToSend.connect(this, &AsyncSocks5UdpSocket::OnInnerReadyToSend);
    udp_->SignalAddressReady.connect(this, &AsyncSocks5UdpSocket::OnInnerAddressReady);
    udp_->SubscribeCloseEvent(this, [this](rtc::AsyncPacketSocket* socket, int err) {
        OnInnerClosed(socket, err);
    });

    if (!socket_factory) {
        RTC_LOG(LS_ERROR) << "AsyncSocks5UdpSocket: null socket factory, cannot ASSOCIATE";
        Fail(EINVAL);
        return;
    }
    rtc::Socket* raw = socket_factory->CreateSocket(destination_.family(), SOCK_STREAM);
    if (!raw) {
        RTC_LOG(LS_ERROR) << "AsyncSocks5UdpSocket: failed to create TCP control socket";
        Fail(EINVAL);
        return;
    }
    control_ = new AsyncSocks5ProxySocket(raw, proxy.address, proxy.username, proxy.password);
    control_->SetUdpAssociate();
    control_->SignalConnectEvent.connect(this, &AsyncSocks5UdpSocket::OnControlConnected);
    control_->SignalCloseEvent.connect(this, &AsyncSocks5UdpSocket::OnControlClosed);
    if (control_->Connect(rtc::SocketAddress()) < 0 &&
        control_->GetState() == rtc::Socket::CS_CLOSED) {
        RTC_LOG(LS_ERROR) << "AsyncSocks5UdpSocket: TCP connect to relay failed immediately, error="
                          << control_->GetError();
        Fail(control_->GetError());
        return;
    }
}

AsyncSocks5UdpSocket::~AsyncSocks5UdpSocket() {
    destroying_ = true;
    if (udp_) {
        udp_->DeregisterReceivedPacketCallback();
    }
    // Deleting the control socket closes the TCP connection, which is the
    // relay's signal to tear the association down.
    delete control_;
    delete udp_;
}

int AsyncSocks5UdpSocket::Send(const void* pv, size_t cb, const rtc::PacketOptions& options) {
    return SendTo(pv, cb, destination_, options);
}

int AsyncSocks5UdpSocket::SendTo(const void* pv, size_t cb, const rtc::SocketAddress& addr, const rtc::PacketOptions& options) {
    if (state_ == STATE_CLOSED || destroying_) {
        return -1;
    }
    if (state_ != STATE_CONNECTED) {
        // Association not up yet: queue (the reflector hello is sent the
        // moment the port is created). Cap the queue; the hello is
        // retransmitted every 500ms until the reflector answers.
        if (pending_.size() >= kMaxQueuedPackets) {
            pending_.pop_front();
        }
        rtc::CopyOnWriteBuffer buf;
        buf.AppendData(static_cast<const uint8_t*>(pv), cb);
        pending_.emplace_back(addr, std::move(buf));
        return static_cast<int>(cb);
    }
    rtc::CopyOnWriteBuffer wrapped;
    if (!AppendUdpHeader(&wrapped, addr)) {
        RTC_LOG(LS_ERROR) << "AsyncSocks5UdpSocket: cannot build UDP header for "
                          << addr.ToSensitiveString();
        return -1;
    }
    wrapped.AppendData(static_cast<const uint8_t*>(pv), cb);
    int sent = udp_->SendTo(wrapped.cdata(), wrapped.size(), bound_, options);
    if (sent < 0) {
        RTC_LOG(LS_WARNING) << "AsyncSocks5UdpSocket: SendTo relay failed, error=" << udp_->GetError();
        return -1;
    }
    return static_cast<int>(cb);
}

rtc::SocketAddress AsyncSocks5UdpSocket::GetLocalAddress() const {
    return udp_ ? udp_->GetLocalAddress() : rtc::SocketAddress();
}

rtc::SocketAddress AsyncSocks5UdpSocket::GetRemoteAddress() const {
    return destination_;
}

int AsyncSocks5UdpSocket::Close() {
    if (state_ == STATE_CLOSED) {
        return 0;
    }
    state_ = STATE_CLOSED;
    pending_.clear();
    if (control_) {
        control_->Close();
    }
    if (udp_) {
        udp_->Close();
    }
    return 0;
}

AsyncSocks5UdpSocket::State AsyncSocks5UdpSocket::GetState() const {
    return state_;
}

int AsyncSocks5UdpSocket::GetOption(rtc::Socket::Option opt, int* value) {
    if (!udp_) {
        return -1;
    }
    return udp_->GetOption(opt, value);
}

int AsyncSocks5UdpSocket::SetOption(rtc::Socket::Option opt, int value) {
    if (!udp_) {
        return -1;
    }
    return udp_->SetOption(opt, value);
}

int AsyncSocks5UdpSocket::GetError() const {
    if (error_ != 0) {
        return error_;
    }
    return udp_ ? udp_->GetError() : 0;
}

void AsyncSocks5UdpSocket::SetError(int error) {
    error_ = error;
    if (udp_) {
        udp_->SetError(error);
    }
}

void AsyncSocks5UdpSocket::OnControlConnected(rtc::Socket* socket) {
    if (destroying_) {
        return;
    }
    bound_ = control_->bound_address();
    if (bound_.IsNil()) {
        RTC_LOG(LS_ERROR) << "AsyncSocks5UdpSocket: ASSOCIATE succeeded but BND is empty";
        Fail(ECONNREFUSED);
        return;
    }
    RTC_LOG(LS_INFO) << "SG-UDP associate=ok bnd=" << bound_.ToString()
                     << " reflector=" << destination_.ToString()
                     << " queued=" << pending_.size();
    state_ = STATE_CONNECTED;
    FlushQueue();
    SignalReadyToSend(this);
}

void AsyncSocks5UdpSocket::OnControlClosed(rtc::Socket* socket, int err) {
    if (destroying_) {
        return;
    }
    RTC_LOG(LS_ERROR) << "AsyncSocks5UdpSocket: relay TCP connection closed, err=" << err
                      << (state_ == STATE_CONNECTED ? " (association lost mid-call)"
                                                    : " (ASSOCIATE handshake failed)");
    Fail(err != 0 ? err : ECONNRESET);
}

void AsyncSocks5UdpSocket::OnUdpPacket(rtc::AsyncPacketSocket* socket, const rtc::ReceivedPacket& packet) {
    if (destroying_ || state_ == STATE_CLOSED) {
        return;
    }
    const uint8_t* data = packet.payload().data();
    size_t size = packet.payload().size();
    rtc::SocketAddress src;
    size_t payload_offset = 0;
    if (!ParseUdpHeader(data, size, &src, &payload_offset)) {
        // Not a SOCKS5 UDP datagram (e.g. a stray direct packet): drop.
        RTC_LOG(LS_WARNING) << "AsyncSocks5UdpSocket: dropping non-SOCKS UDP packet ("
                            << size << " bytes)";
        return;
    }
    if (src != destination_) {
        RTC_LOG(LS_WARNING) << "AsyncSocks5UdpSocket: relay delivered packet from "
                            << src.ToSensitiveString() << ", expected "
                            << destination_.ToSensitiveString();
        // Still deliver: the port above validates the source and drops
        // anything that is not its reflector.
    }
    if (!first_media_seen_) {
        first_media_seen_ = true;
        // Canonical marker for the v2.0.22 debug report: the first relayed
        // media packet arrived. associate=ok alone only proves the relay
        // accepted the association, not that the reflector answers.
        RTC_LOG(LS_INFO) << "SG-UDP first-media reflector=" << src.ToString();
    }
    int64_t packet_time_us = -1;
    if (packet.arrival_time().has_value()) {
        packet_time_us = packet.arrival_time()->us_or(-1);
    }
    // src and the payload view stay alive for this synchronous delivery:
    // the port's OnReadPacket handles the packet before returning.
    NotifyPacketReceived(rtc::ReceivedPacket::CreateFromLegacy(
        data + payload_offset, size - payload_offset, packet_time_us, src));
}

void AsyncSocks5UdpSocket::OnInnerSentPacket(rtc::AsyncPacketSocket* socket, const rtc::SentPacket& sent_packet) {
    if (destroying_) {
        return;
    }
    SignalSentPacket(this, sent_packet);
}

void AsyncSocks5UdpSocket::OnInnerReadyToSend(rtc::AsyncPacketSocket* socket) {
    if (destroying_) {
        return;
    }
    if (state_ == STATE_CONNECTED) {
        SignalReadyToSend(this);
    }
}

void AsyncSocks5UdpSocket::OnInnerAddressReady(rtc::AsyncPacketSocket* socket, const rtc::SocketAddress& address) {
    if (destroying_) {
        return;
    }
    SignalAddressReady(this, address);
}

void AsyncSocks5UdpSocket::OnInnerClosed(rtc::AsyncPacketSocket* socket, int err) {
    if (destroying_) {
        return;
    }
    RTC_LOG(LS_ERROR) << "AsyncSocks5UdpSocket: local UDP socket closed, err=" << err;
    Fail(err != 0 ? err : ECONNRESET);
}

void AsyncSocks5UdpSocket::FlushQueue() {
    if (pending_.empty()) {
        return;
    }
    RTC_LOG(LS_INFO) << "AsyncSocks5UdpSocket: flushing " << pending_.size()
                     << " queued packet(s) to relay";
    auto queued = std::move(pending_);
    pending_.clear();
    for (auto& item : queued) {
        SendTo(item.second.cdata(), item.second.size(), item.first, rtc::PacketOptions());
    }
}

void AsyncSocks5UdpSocket::Fail(int error) {
    if (state_ == STATE_CLOSED) {
        return;
    }
    // Canonical marker for the v2.0.22 debug report: phase=handshake (the
    // ASSOCIATE never completed) vs midcall (association lost after it was
    // up). Parsed out of FinalState.debugLog by VoIPService.onTgVoipStop.
    RTC_LOG(LS_ERROR) << "SG-UDP associate=failed phase="
                      << (state_ == STATE_CONNECTED ? "midcall" : "handshake")
                      << " error=" << error
                      << " reflector=" << destination_.ToString()
                      << " queued=" << pending_.size();
    error_ = error;
    state_ = STATE_CLOSED;
    pending_.clear();
    if (control_) {
        control_->Close();
    }
    if (udp_) {
        udp_->Close();
    }
    NotifyClosed(error);
}

} // namespace tgcalls
