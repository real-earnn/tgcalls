#include "v2/Socks5ProxySocket.h"

#include <cstdint>
#include <cstring>

#include <netinet/in.h>

#include "rtc_base/byte_order.h"
#include "rtc_base/logging.h"

namespace tgcalls {

AsyncSocks5ProxySocket::AsyncSocks5ProxySocket(rtc::Socket* socket,
                                               const rtc::SocketAddress& proxy,
                                               const std::string& username,
                                               const rtc::CryptString& password)
    : BufferedReadAdapter(socket, 1024),
      proxy_(proxy),
      user_(username),
      pass_(password),
      state_(PS_ERROR) {
}

AsyncSocks5ProxySocket::~AsyncSocks5ProxySocket() {
}

int AsyncSocks5ProxySocket::Connect(const rtc::SocketAddress& addr) {
    RTC_LOG(LS_VERBOSE) << "AsyncSocks5ProxySocket::Connect("
                        << proxy_.ToSensitiveString() << " -> "
                        << addr.ToSensitiveString() << ")";
    dest_ = addr;
    state_ = PS_INIT;
    BufferInput(true);
    return BufferedReadAdapter::Connect(proxy_);
}

rtc::SocketAddress AsyncSocks5ProxySocket::GetRemoteAddress() const {
    return dest_;
}

int AsyncSocks5ProxySocket::Close() {
    state_ = PS_ERROR;
    dest_.Clear();
    return BufferedReadAdapter::Close();
}

rtc::Socket::ConnState AsyncSocks5ProxySocket::GetState() const {
    if (state_ < PS_TUNNEL) {
        return CS_CONNECTING;
    } else if (state_ == PS_TUNNEL) {
        return CS_CONNECTED;
    } else {
        return CS_CLOSED;
    }
}

void AsyncSocks5ProxySocket::OnConnectEvent(rtc::Socket* socket) {
    RTC_LOG(LS_VERBOSE) << "AsyncSocks5ProxySocket::OnConnectEvent";
    SendGreeting();
}

void AsyncSocks5ProxySocket::OnCloseEvent(rtc::Socket* socket, int err) {
    RTC_LOG(LS_VERBOSE) << "AsyncSocks5ProxySocket::OnCloseEvent(" << err << ")";
    BufferedReadAdapter::OnCloseEvent(socket, err);
}

void AsyncSocks5ProxySocket::SendGreeting() {
    // VER=5, NMETHODS=1, METHODS=[0x02 user/pass] or [0x00 no auth].
    // sgrelay requires auth (replies 0xff if none offered), so offer 0x02
    // whenever we have a username.
    uint8_t greeting[3];
    greeting[0] = 0x05;
    greeting[1] = 0x01;
    if (user_.empty()) {
        greeting[2] = 0x00;
        authOffered_ = false;
    } else {
        greeting[2] = 0x02;
        authOffered_ = true;
    }
    DirectSend(greeting, sizeof(greeting));
    state_ = PS_GREETING;
}

void AsyncSocks5ProxySocket::SendAuth() {
    // RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD.
    std::string password;
    password.resize(pass_.GetLength());
    if (!password.empty()) {
        pass_.CopyTo(password.data(), false);
    }
    if (user_.size() > 255 || password.size() > 255) {
        RTC_LOG(LS_ERROR) << "SOCKS5 credentials too long";
        Error(EINVAL);
        return;
    }
    std::string request;
    request.push_back(0x01);
    request.push_back(static_cast<char>(user_.size()));
    request.append(user_);
    request.push_back(static_cast<char>(password.size()));
    request.append(password);
    DirectSend(request.data(), request.size());
    state_ = PS_AUTH;
}

void AsyncSocks5ProxySocket::SendConnectRequest() {
    // VER=5, CMD=1 (CONNECT), RSV=0, ATYP, DST.ADDR, DST.PORT.
    std::string request;
    request.push_back(0x05);
    request.push_back(0x01);
    request.push_back(0x00);
    if (!dest_.hostname().empty() && dest_.ipaddr().IsNil()) {
        // Unresolved hostname: domain form.
        if (dest_.hostname().size() > 255) {
            RTC_LOG(LS_ERROR) << "SOCKS5 destination hostname too long";
            Error(EINVAL);
            return;
        }
        request.push_back(0x03);
        request.push_back(static_cast<char>(dest_.hostname().size()));
        request.append(dest_.hostname());
    } else if (dest_.ipaddr().family() == AF_INET) {
        request.push_back(0x01);
        in_addr v4 = dest_.ipaddr().ipv4_address();
        request.append(reinterpret_cast<const char*>(&v4.s_addr), 4);
    } else {
        request.push_back(0x04);
        in6_addr v6 = dest_.ipaddr().ipv6_address();
        request.append(reinterpret_cast<const char*>(&v6.s6_addr), 16);
    }
    uint16_t port = rtc::HostToNetwork16(static_cast<uint16_t>(dest_.port()));
    request.append(reinterpret_cast<const char*>(&port), 2);
    DirectSend(request.data(), request.size());
    state_ = PS_CONNECT;
}

void AsyncSocks5ProxySocket::ProcessInput(char* data, size_t* len) {
    size_t pos = 0;
    while (state_ != PS_TUNNEL && state_ != PS_ERROR && pos < *len) {
        if (state_ == PS_GREETING) {
            if (*len - pos < 2) {
                break; // wait for the rest of the method-selection reply
            }
            if (data[pos] != 0x05) {
                RTC_LOG(LS_ERROR) << "SOCKS5: bad version in greeting reply";
                Error(ECONNREFUSED);
                break;
            }
            uint8_t method = static_cast<uint8_t>(data[pos + 1]);
            pos += 2;
            if (method == 0x00) {
                SendConnectRequest();
            } else if (method == 0x02) {
                SendAuth();
            } else {
                RTC_LOG(LS_ERROR) << "SOCKS5: no acceptable auth method (" << (int)method << ")";
                Error(EACCES);
            }
        } else if (state_ == PS_AUTH) {
            if (*len - pos < 2) {
                break;
            }
            if (data[pos] != 0x01 || data[pos + 1] != 0x00) {
                RTC_LOG(LS_ERROR) << "SOCKS5: auth failed";
                Error(EACCES);
                break;
            }
            pos += 2;
            SendConnectRequest();
        } else if (state_ == PS_CONNECT) {
            if (*len - pos < 5) {
                break;
            }
            if (data[pos] != 0x05 || data[pos + 1] != 0x00) {
                RTC_LOG(LS_ERROR) << "SOCKS5: CONNECT failed, rep=" << (int)(uint8_t)data[pos + 1];
                Error(ECONNREFUSED);
                break;
            }
            uint8_t atyp = static_cast<uint8_t>(data[pos + 3]);
            size_t addrLen;
            if (atyp == 0x01) {
                addrLen = 4;
            } else if (atyp == 0x04) {
                addrLen = 16;
            } else if (atyp == 0x03) {
                if (*len - pos < 5) {
                    break;
                }
                addrLen = 1 + static_cast<uint8_t>(data[pos + 4]);
            } else {
                RTC_LOG(LS_ERROR) << "SOCKS5: bad ATYP in CONNECT reply";
                Error(ECONNREFUSED);
                break;
            }
            size_t total = 4 + addrLen + 2;
            if (*len - pos < total) {
                break; // wait for the full reply
            }
            pos += total;
            state_ = PS_TUNNEL;
        } else {
            break;
        }
    }

    *len -= pos;
    if (*len > 0) {
        memmove(data, data + pos, *len);
    }

    if (state_ != PS_TUNNEL) {
        return;
    }

    bool remainder = (*len > 0);
    BufferInput(false);
    SignalConnectEvent(this);
    // If SignalConnect destroys this socket we are in trouble; same caveat
    // as AsyncHttpsProxySocket — remainder bytes are reflector traffic.
    if (remainder) {
        SignalReadEvent(this);
    }
}

void AsyncSocks5ProxySocket::Error(int error) {
    BufferInput(false);
    Close();
    SetError(error);
    SignalCloseEvent(this, error);
}

} // namespace tgcalls
