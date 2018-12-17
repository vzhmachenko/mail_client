

#include <cstdio>
#include <cstring>
#include <iostream>

#include <vector>
#include "imap.h"
#include "socket.h"
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
void Socket::receive(std::string& str){
    char buf[1024];
    std::string bb;
     while(1) {
        int err = SSL_read(ssl, buf, sizeof(buf) -1);
        if(err < 0){
            std::cout<<"SSL reading error\n";
            return;
        }
        buf[err] = '\0';
        std::cout<<buf<<std::endl;
        bb = buf;
        if( bb.find(str) >= 0 )
            return;
    }
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
        std::cout<<"0 - manual 1-login  2-...\n";
        std::cin>>command;

        if(command == '0'){     //manual command;
            std::cout<<"Manual command format: command args\n";
            std::cin.get();
            imap.userCommand(); 
        }
        else if(command == '1'){
            imap.login(argv[1], argv[2]);
        } else if (command == '2'){
            Socket::receive(unic2);
        }
        else return 0;
    }

/*
	buf[1024];

	while(1){
		p = BIO_read(bio, r_buf, 1023);
		printf("**********************\n");
		printf("*Message size = %d*\n", p);
		printf("**********************\n");

		if(p <= 0) 
			break;
		r_buf[p] = '\0';
		printf("%s", r_buf);
		printf("q-exit>> ");
        std::cin.getline(w_buf, 1023);
		if(w_buf[0] == 'q')
			break;
		else{
			int len = strlen(w_buf);
			w_buf[len + 0] = '\r';
			w_buf[len + 1] = '\n';
			w_buf[len + 2] = '\0';
			p = BIO_write(bio, w_buf, strlen(w_buf));
			printf("==============================\n");
		}


	}

	printf("All is OK!");
	// Close the connection and free the context
	BIO_free_all(bio);
	SSL_CTX_free(ctx);*/
	return 0;
}