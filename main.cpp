

#include <cstdio>
#include <cstring>
#include <iostream>

#include <vector>
#include "imap.h"
#include "socket.h"

//add new some texxt


//--------------------------------------------------------------
//-------------IMAP---CLASS-------------------------------------
//--------------------------------------------------------------
IMAP::IMAP(const std::string &host, int port){
    std::tuple<bool, std::string> sock = 
                socket.create(host, port);
    if(!std::get<0>(sock)) 
        std::cout<<std::get<1>(sock)<<std::endl;

    std::tuple<bool, std::string> ssl = socket.createSSL();
    if (!std::get<0>(ssl))
        std::cout<<std::get<1>(ssl) << std::endl;
}

bool IMAP::login(const std::string &username, 
                const std::string &password){
    std::string command = ". login " + username + " " + password +
    "\r\n"; 
    socket.send(command);
    



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
bool Socket::send(const std::string &s){
    int err = SSL_write(ssl, s.c_str(), s.size() );
    if(err == -1){
        std::cout<< "Socket send command ERROR";
        return false;
    }
    return true;
}
std::string Socket::receive(){

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
    

/*
	BIO *bio;
	SSL *ssl;
	SSL_CTX *ctx;
    

	int p;

	char r_buf[1024];

	// Set up the library
	ERR_load_BIO_strings();

	//SSL_library_init()  -- load encryption & hash algorithms
	SSL_load_error_strings();	//load error strings for error reporting
	OpenSSL_add_all_algorithms();
	
	// Set up the SSL context
	//method = SSLv23_client_method()
	ctx = SSL_CTX_new(SSLv23_client_method());
	if(!SSL_CTX_load_verify_locations(ctx, 
				"/etc/ssl/certs/ca-certificates.crt", NULL)){
		fprintf(stderr, "Error loading trust store\n");
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		return 0;
	}
	// Setup the connection
	bio = BIO_new_ssl_connect(ctx);
    std::cout<<"Hello";
	// Set the mode flag
	BIO_get_ssl(bio, &ssl);	//error
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	// Create and setup connection
	BIO_set_conn_hostname(bio, "imap.ukr.net:993");
	//BIO_set_conn_hostname(bio, "gordonua.com:https");
	if(BIO_do_connect(bio) <= 0){
		fprintf(stderr, "Error attempting to connect\n");
		ERR_print_errors_fp(stderr);
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
		return 0;
	}

	// Check the certificate
	if(SSL_get_verify_result(ssl) != X509_V_OK){
		fprintf(stderr, "Certificate verification error: %i\n", 
			SSL_get_verify_result(ssl) );
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
		return 0;
	}

	// Read the response
	char w_buf[1024];

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