

#include <cstdio>
#include <cstring>
#include <iostream>

#include <vector>
#include "imap.h"
#include "socket.h"


//--------------------------------------------------------------
//-------------IMAP---CLASS-------------------------------------
//--------------------------------------------------------------
IMAP::IMAP(const std::string &host, int port){
    std::tuple<bool, std::strinsdafj 
    fadsf ala
    dsf d
     ds
     for (int i = 0; i <  dsfdfs; ++i)
     {
         /* code */
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
    char *req = "GET / HTTP/1.1\r\nHost: www.pravda.com.ua\r\n\r\n";    
    SSL_write(ssl, req, strlen(req));
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

//--------------------------------------------------------------
//--------------------------------------------------------------
//--------------------------------------------------------------


std::vector<std::string> menu_functions{"Boxes", "Quit", "Quit"};



int main(int argc, char *argv[]){
    if(argc < 3){
        std::cout<< "You should use this"<<
        " program like: ./progname login@ukr.net password\n";
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
    
	return 0;
}
