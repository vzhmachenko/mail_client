#include <iostream>
#include <string>
#include <cstring>

struct config{
    int imap_port;
    int smtp_port
    std::string imap_server;
    std::string smtp_server;
    std::string user_name;
    std::string password;
    std::string name;
};



std::vector<std::string> vocabulory{"help",   "send",     "quit",   "read",
                                    "search", "delete",   "sync",   "list",
                                    "create", "deletemb", "rename", "move",
                                    "noop"};




int main(int argc, char **argv) {

    std::cout<< "IMAP Mail Client\n";
    config config{  993,
                    465,
                    "imap.ukr.net",
                    "smtp.ukr.net",
                    "ssppoo@ukr.net",
                    "password",
                    "Valentyn Zhmachenko"};












  return 0;
}

