

#include <cstdio>
#include <cstring>
#include <iostream>
#include <cctype>    //isdigit isblank


#include <vector>
#include "imap.h"
#include "socket.h"
#include "base64.h"
#include <algorithm>


//add new some texxt


//--------------------------------------------------------------
//-------------IMAP---CLASS-------------------------------------
//--------------------------------------------------------------
IMAP::IMAP(const std::string &host, int port){
    std::tuple<bool, std::string> sock = 
                socket.create(host, port);
    unic = "unicEmailTag ";
    if(!std::get<0>(sock)) 
        std::cout<<std::get<1>(sock)<<std::endl;

    std::tuple<bool, std::string> ssl = socket.createSSL();
    if (!std::get<0>(ssl))
        std::cout<<std::get<1>(ssl) << std::endl;
}

bool IMAP::login(const std::string &username, 
                const std::string &password){
    std::string command = unic + "login " + username + " " + password +
    "\r\n"; 
    std::cout<<command;

    socket.send(command);
    socket.receive(unic);
    command = unic + "select inbox\r\n";
    socket.send(command);
    socket.receive(unic);
}
void IMAP::userCommand(){
    std::string buf;
    std::getline(std::cin, buf);
    buf = unic +buf + "\r\n"; 
    socket.send(buf);
    socket.receive(unic);
}
void IMAP::receive(){
    socket.receive(unic);
}
void IMAP::list(){
    std::string buf = unic + "uid search all\r\n"; 
    socket.send(buf);
    std::string listOfMessages = socket.receive(unic, false);
    std::vector<int> numericList;
    std::string::size_type i=1;
    int digit = 0;
    while(!isdigit(listOfMessages[++digit]) )
        ;
    listOfMessages.erase(0, digit-1);
    while(isdigit(listOfMessages[i]) || isblank(listOfMessages[i])){
        listOfMessages.erase(0, i);
        numericList.push_back(std::stoi(listOfMessages, &i));
    } 
    std::cout<< "Size of vetor: " << numericList.size()<<std::endl;
            //std::vector<int>::reverse_iterator rit = 
            //            numericList.rbegin();
            int rit = numericList.size()-1;
    char ch;
    std::cout<<"Show last 5 messages: press +\n";
    std::cin>>ch;
    while(ch == '+' || ch == '-'){

        Mail mail;
        for(int i = 0; i<5; i++){
            mail.subject = Subject(std::to_string(numericList.at(rit)));
            mail.date = Date(std::to_string(numericList.at(rit)));
            mail.from = From(std::to_string(numericList.at(rit)));
            std::cout<<"\n----------msg#"<<5-abs(i)<<"------------\n";
            std::cout<<"From: "<< mail.from;
            std::cout<<"Date: "<< mail.date;
            std::cout<<"Subject: "<< mail.subject;
            if(ch == '+')
                rit--;
            else
                rit++;
        }
        std::cout<<"********************************\n"
                    "Print previous 5 mails press +:\n"
                    "********************************\n";
        std::cin>>ch;
        while(isdigit(ch) ){
            mail.text = Text(std::to_string(numericList.at(rit + (int)ch -48)));
            std::cout<<":::TEXT:::\n";
            std::cout<<mail.text;

            std::cin>>ch;
        }



        


    }
}
/*
uid fetch 5838 (BODY[HEADER.FIELDS (from to subject date)])
uid fetch 5839 body[1]\r\n";  */  
std::string IMAP::Text(std::string numMsg){    
    std::string buf = unic + "uid fetch " + numMsg +
        " (BODY[1])\r\n";
    std::string &mailText = buf;   
    socket.send(buf);
    mailText = socket.receive(unic, 1);
    std::size_t begin = 0;
    begin = mailText.find("Date:");
    mailText = mailText.substr(begin+6, 25);
    return mailText+"\n";
}                  
std::string IMAP::Date(std::string numMsg){    
    std::string buf = unic + "uid fetch " + numMsg +
        " (BODY[HEADER.FIELDS (date)])\r\n";
    std::string &mailDate = buf;   
    socket.send(buf);
    mailDate = socket.receive(unic, false);
    std::size_t begin = 0;
    begin = mailDate.find("Date:");
    mailDate = mailDate.substr(begin+6, 25);
    return mailDate+"\n";
}
std::string IMAP::From(std::string numMsg){
    std::string buf = unic + "uid fetch " + numMsg +
        " (BODY[HEADER.FIELDS (from)])\r\n";
    std::string &mailFrom = buf;   
    socket.send(buf);
    mailFrom = socket.receive(unic, 0);
    std::size_t begin;
    begin = mailFrom.find("<");
    if(begin == std::string::npos)
        begin = mailFrom.find("From")+6;
    mailFrom = mailFrom.substr(begin, mailFrom.find("UID")-begin-2);
    return mailFrom;
}
std::string IMAP::Subject(std::string numMsg){
    std::string buf = unic + "uid fetch " + numMsg +
        " (BODY[HEADER.FIELDS (from to subject date)])\r\n";
    std::string &mailHeader = buf;   
    socket.send(buf);
    mailHeader = socket.receive(unic, false);

    std::vector<std::string> subject;
    std::size_t begin = 0, end = 0;
    bool cyrillic = 0;
    while(1){
        begin = mailHeader.find("=?UTF-8?B?", begin);
        if(begin == std::string::npos){
            if(cyrillic){
                subject.push_back("\n");
                break;
            }
            begin = mailHeader.find("Subject:");
            end = mailHeader.find("UID");
            subject.push_back(mailHeader.substr(begin+9, 
            end - begin-12));

            break;
        }            
        end = mailHeader.find("?=", end);
        subject.push_back(mailHeader.substr(begin+10, 
                            end - begin-10));
        begin = end++;
        cyrillic = true;
    }
    mailHeader.clear();
    for(int i=0;i<subject.size(); ++i)
        if(cyrillic)
           mailHeader += base64_decode(subject.at(i));
        else
            mailHeader = subject.at(i);

        if(cyrillic)
            mailHeader += "\n";
    return mailHeader;
}
//--------------------------------------------------------------
//-------------SOCKET---CLASS-----------------------------------
//--------------------------------------------------------------
std::tuple<bool, std::string> Socket::create(
    std::string hostname ,int port){
    ssl = NULL;
    
    struct hostent *host;
    struct sockaddr_in addr;

    if((host = gethostbyname(hostname.c_str() )) == NULL)
        return std::make_tuple(false, "DNS failded.");
    
    sockid = socket(AF_INET, SOCK_STREAM, 0);
    if(sockid == -1)
        return std::make_tuple(false, "Socket create error");
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if(connect(sockid, (struct sockaddr*)&addr, 
                        sizeof(addr)) != 0){
        close(sockid);
        return std::make_tuple(false, "Socket connect error");
    }
    return std::make_tuple(true, "Connected soccesfull!");
}

std::tuple<bool, std::string> Socket::createSSL(){
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = SSLv23_method();
    ctx = SSL_CTX_new(method);

    if(ctx == NULL)
        return std::make_tuple(false, "CTX creating error.");
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockid);
    if(SSL_connect(ssl) < 0)
        ERR_print_errors_fp(stderr);
    else{//certificate view
        X509 *cert;  
        cert = SSL_get_peer_certificate(ssl);
        char *line;
        if (cert != NULL){
            std::cout<< "Server certificates:\n";
            line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
            printf("Subject: %s\n", line);
            
            free(line); /* free the malloc'ed string */
            line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
            printf("Issuer: %s\n", line);
            free(line);      /* free the malloc'ed string */
            X509_free(cert); /* free the malloc'ed certificate copy */
        }
    else
        return std::make_tuple(false, "No certificate.");
    
    std::string reply = "";

    int err = 0;
    char buf[1024];
    //char *req = "GET / HTTP/1.1\r\nHost: \r\n\r\n";    
    //SSL_write(ssl, req, strlen(req));
    do {
        err = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (err < 0) return std::make_tuple(false, "SSL_read failed.");
        buf[err] = '\0';
        reply += std::string(buf);
    } while (err == sizeof(buf) - 1);

    std::cerr << "Received: " << reply << std::endl;

    SSL_set_read_ahead(ssl, 1);
  }

  return std::make_tuple(true, "");
}
bool Socket::send(const std::string &s){
    int err = SSL_write(ssl, s.c_str(), s.size() );
    if(err == -1){
        std::cout<< "Socket send command ERROR";
        return false;
    }
    return true;
}
std::string Socket::receive(std::string& str, bool show){
    char buf[1024];
    std::string bb = "";
    bool endOfMessage = false;
     while( !endOfMessage ) {
        int err = SSL_read(ssl, buf, sizeof(buf) -1);
        if(err < 0){
            std::cout<<"SSL reading error\n";
            return 0;
        }
        buf[err] = '\0';
        bb += buf;
        std::size_t found = bb.find(str);
        if( found != std::string::npos ){
            endOfMessage = true;
        }

    }
    if(show)
        std::cout<<bb;
    return bb;

/*OK, NO, BAD, PREAUTH and BYE*/


}

Socket::~Socket(){
    SSL_shutdown(ssl);
    close(sockid);
    SSL_CTX_free(ctx);
    SSL_free(ssl);
}


//--------------------------------------------------------------
//--------------------------------------------------------------
//--------------------------------------------------------------


std::vector<std::string> menu_functions{"Boxes", "Quit", "Quit"};



int main(int argc, char *argv[]){
    if(argc < 3){
        std::cout<< "You should use this"<<
        " program like: ./pr login@ukr.net password\n";
    exit(0);
    }

    config authent{ 993,
                    465,
                    "imap.ukr.net",
                    "smtp.ukr.net",
                    (std::string)argv[1]+"@ukr.net",
                    argv[2],
                    "VZM"};
    IMAP imap(authent.imap_server, authent.imap_port);
    char command;
    std::string unic2 = "unicEmailTag ";
    while(1){   //test 
        std::cout<<"--------------------------------\n";
        std::cout<<"0 - manual 1-login  2-receive 3-list\n";
        std::cin>>command;

        if(command == '0'){     //manual command;
            std::cout<<"Manual command format: command args\n";
            std::cin.get();
            imap.userCommand(); 
        }
        else if(command == '1'){
            imap.login(argv[1], argv[2]);
        } else if (command == '2'){
            imap.receive();
        } else if (command == '3'){
            imap.list();
        }
        else return 0;
    }

/*


	printf("All is OK!");
	// Close the connection and free the context
	BIO_free_all(bio);
	SSL_CTX_free(ctx);*/
	return 0;
}