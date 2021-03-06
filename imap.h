
#ifndef IMAP_H
#define IMAP_H

#include <iostream>
#include <string>
#include <vector>
#include <tuple>

#include "socket.h"

struct config{
    int imap_port;
    int smtp_port;
    std::string imap_server;
    std::string smtp_server;
    std::string username;
    std::string password;
    std::string nameInMailSign;

};

struct Mail{
    int uid;
    std::string from;
    std::string subject;
    std::string date;
    std::string text;
};

class IMAP{
public:
    IMAP(const std::string &host, int port);

    bool login(const std::string &username, 
                const std::string &password);
    bool noop();
    bool logout();
    bool selectMailbox(const std::string &mailbox);
    void userCommand();
    void receive();
    void list();
    std::string Subject(std::string);
    std::string Date(std::string);
    std::string From(std::string);
    std::string Text(std::string);    





private:
    Socket socket;
    std::string username;
    std::string password;
    std::string unic;

};




#endif