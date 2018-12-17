#ifndef SOCKET_H
#define SOCKET_H
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <string>
#include <tuple>
#include <iostream>

#include <fcntl.h>
#include <unistd.h>
#include <string>
#include <tuple>

#include <openssl/crypto.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <chrono>
#include <mutex>
#include <queue>
#include <regex>
#include <thread>


class Socket{
public:
    std::tuple<bool, std::string> create(std::string hostname, int port);
    std::tuple<bool, std::string> createSSL();
    bool send(const std::string &s);
    void receive();

    ~Socket();
private:
    int sockid;
    SSL_CTX *ctx;
    SSL *ssl;

};




#endif