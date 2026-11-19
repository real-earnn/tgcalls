#ifndef TGCALLS_SOCKS5_PROXY_SOCKET_H
#define TGCALLS_SOCKS5_PROXY_SOCKET_H

#include <string>

#include "rtc_base/proxy_info.h"
#include "rtc_base/socket_adapters.h"

namespace tgcalls {

// Async SOCKS5 (RFC 1928 + RFC 1929 username/password) client adapter.
// Connect(dest) opens TCP to the proxy, runs greeting -> auth -> CONNECT
// asynchronously, and signals connect once the tunnel to dest is up.
// After that it is a plain byte pipe. Used by ReflectorPort so a TCP
// reflector connection goes through the user's SOCKS5 relay instead of
// direct to Telegram (which is blocked for our users).
class AsyncSocks5ProxySocket : public rtc::BufferedReadAdapter {
public:
    AsyncSocks5ProxySocket(rtc::Socket* socket,
                           const rtc::SocketAddress& proxy,
                           const std::string& username,
                           const rtc::CryptString& password);
    ~AsyncSocks5ProxySocket() override;

    AsyncSocks5ProxySocket(const AsyncSocks5ProxySocket&) = delete;
    AsyncSocks5ProxySocket& operator=(const AsyncSocks5ProxySocket&) = delete;

    int Connect(const rtc::SocketAddress& addr) override;
    rtc::SocketAddress GetRemoteAddress() const override;
    int Close() override;
    rtc::Socket::ConnState GetState() const override;

protected:
    void OnConnectEvent(rtc::Socket* socket) override;
    void OnCloseEvent(rtc::Socket* socket, int err) override;
    void ProcessInput(char* data, size_t* len) override;

    void SendGreeting();
    void SendAuth();
    void SendConnectRequest();
    void Error(int error);

private:
    rtc::SocketAddress proxy_, dest_;
    std::string user_;
    rtc::CryptString pass_;
    enum ProxyState {
        PS_INIT,
        PS_GREETING,
        PS_AUTH,
        PS_CONNECT,
        PS_TUNNEL,
        PS_ERROR
    } state_;
    bool authOffered_ = false;
};

} // namespace tgcalls

#endif // TGCALLS_SOCKS5_PROXY_SOCKET_H
