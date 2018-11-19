 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <stdarg.h>
 #include <errno.h>
 #include <netdb.h>
 #include <fcntl.h>
 #include <sys/time.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 
int main( int argc)
{
	printf("1\n");
 	struct addrinfo adr, *res;
 	int s, len;
 	memset(&adr, 0, sizeof (adr));
 	adr.ai_family = AF_INET;
 	adr.ai_flags = AI_PASSIVE;
 	adr.ai_socktype = SOCK_STREAM;
	printf("2\n");

 	getaddrinfo("127.0.0.1", "9055", &adr, &res);
 	s = socket(res->ai_family, res->ai_socktype, 0);
 	connect(s, res->ai_addr, res->ai_addrlen);
 	int rc; char buf[120];
 	printf("3\n");
 	
	while ( fgets( buf, sizeof( buf ), stdin ) != NULL ){
			len = strlen( buf );
			rc = send( s, buf, len, 0 );			
			rc = recv( s, buf, sizeof( buf ),0 );
			fputs( buf, stdout );
			recv(s, buf, sizeof(buf), 0);
		printf("%s\n", buf);
		}
 	 		printf("4n");

return 0;
}
