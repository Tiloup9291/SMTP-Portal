/*
 *The executable Portal from the project SMTP Portal
 *Copyright (C) 2025  John Doe

 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation, version 3 of the License, GPL-3.0-only.

 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.

 *You should have received a copy of the GNU General Public License
 *along with this program.  If not, see <https://www.gnu.org/licenses/>
*/
#define _LISTENER_SOURCE
#include <argp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#include <resolv.h>
#include <arpa/nameser.h>
#include <netinet/in.h>

#define SERVER_SOCKET_ERROR -1
#define SERVER_SETSOCKOPT_ERROR -2
#define SERVER_BIND_ERROR -3
#define SERVER_LISTEN_ERROR -4
#define STDIN_READ_ERROR -5
#define CLIENT_RESOLVE_ERROR -6
#define WRITE_SOCKET_ERROR -7
#define WRITE_STDOUT_ERROR -8
#define SOCKET_READ_ERROR -9
#define HEAP_BUFFER_OVERFLOWED -10
#define DATA_SECTION_OVEFLOWED -11
#define INVALID_POINTER -12

#define BUF_SIZE 65536

typedef enum {TRUE = 1, FALSE = 0} bool;

const char *arpg_program_version = "Portal 1.0";
const char *argp_program_bug_address = "me, John Doe, you know how! ;)";
const char *license = "\n""The executable Portal from the project SMTP Portal\n"
 "Copyright (C) 2025  John Doe\n"
"\n"
 "This program is free software: you can redistribute it and/or modify\n"
 "it under the terms of the GNU General Public License as published by\n"
 "the Free Software Foundation, version 3 of the License, GPL-3.0-only.\n"
"\n"
 "This program is distributed in the hope that it will be useful,\n"
 "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
 "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
 "GNU General Public License for more details.\n"
"\n"
 "You should have received a copy of the GNU General Public License\n"
 "along with this program.  If not, see <https://www.gnu.org/licenses/>\n"
 "\n";
 const char *notice = "\n""Portal from the project SMTP Portal  Copyright (C) 2025 John Doe\n"
    "This program comes with ABSOLUTELY NO WARRANTY; for details type `--show' or '-s'.\n"
    "This is free software, and you are welcome to redistribute it\n"
    "under certain conditions; type `--show' or '-s' for details.\n";
struct arguments{
    //input
    char *bind_addr;
    int local_port;
    //output
    char *outbind_addr;
    int outlocal_port;
    //type
    bool type;
};
static const struct argp_option options[] =
{
    {"bind_addr", 'b', "BIND_ADDR", 0, "Local address to bind the input listener",0},
    {"local_port", 'l', "LOCAL_PORT", 0, "Local port the input bind address listen to",0},
    {"outbind_addr", 'c', "OUTBIND_ADDR", 0, "remote address to connect to",0},
    {"outlocal_port", 'j', "OUTLOCAL_PORT", 0, "remote port the remote bind address connect to",0},
    {"type", 't', "BLACKHOLE[b]/WHITEHOLE[w]", 0, "type of this portal",0},
    {"show", 's', 0, 0, "Show license",0},
    {0}
};
static error_t parse_opt(int key, char* arg, struct argp_state *state){
    struct arguments *arguments = state->input;
    switch(key){
        case 'b':
            if (arguments->bind_addr != NULL){
                free(arguments->bind_addr);
            }
            arguments->bind_addr=(char*)malloc(40*sizeof(char));
            if (arguments->bind_addr == NULL){
                exit(ARGP_ERR_UNKNOWN);
            }
            strncpy(arguments->bind_addr,arg,40);
            break;
        case 'l':
            if (atoi(arg)>=0 && atoi(arg) < 65536){
                arguments->local_port = atoi(arg);
                break;
            }else{
                exit(ARGP_ERR_UNKNOWN);
            }
        case 'c':
            if (arguments->outbind_addr != NULL){
                free(arguments->outbind_addr);
            }
            arguments->outbind_addr=(char*)malloc(40*sizeof(char));
            if (arguments->outbind_addr == NULL){
                exit(ARGP_ERR_UNKNOWN);
            }
            strncpy(arguments->outbind_addr,arg,40);
            break;
        case 'j':
            if (atoi(arg)>=0 && atoi(arg) < 65536){
                arguments->outlocal_port = atoi(arg);
                break;
            }else{
                exit(ARGP_ERR_UNKNOWN);
            }
        case 't':
            if (strcmp(arg, "b") == 0){
                arguments->type = FALSE;
                break;
            }else if (strcmp(arg, "w") == 0){
                arguments->type = TRUE;
                break;
            }else {
              break;
            }
        case 's':
            printf("%s",license);
            exit(0);
        case ARGP_KEY_END:
            if (arguments->local_port == 0){
                argp_failure(state, -10, 1, "required -l and -j See --help for more information\n");
                exit(ARGP_ERR_UNKNOWN);
            }else if (arguments->outlocal_port == 0){
                argp_failure(state, -10, 1, "required -l and -j See --help for more information\n");
                exit(ARGP_ERR_UNKNOWN);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const char doc[] = "Portal -- A program to listen to data receive from client and exchange with a relay.\nFrom me, John Doe. ;)";
static const struct argp argp = {options, parse_opt,0,doc,0,0,0};
struct arguments arguments;

int check_ipversion(char * address);
void closeSockets();
size_t convert_ssize_to_size(ssize_t value);
int createListenerSocket(int port);
void forward_data(int source_sock);
void forward_data_w(int source_sock);
void handle_client(int client_sock);
void listenerLoop();
void printMessage(const char *format, ...);
void sigchld_handler(int sig);
void sigterm_handler(int sig);
int searchDomain(char *message);
int connect_to_remote(char* host, int port);
char* get_mx_record(char* domain);

int server_sock,client_sock, remote_socket = 0;
int connections_processed = 0;
char *domain = NULL;
int domainSize = 0;

#define BACKLOG 20 // how many pending connections queue will hold

int main(int argc, char *argv[])
{
    arguments.bind_addr = NULL;
    arguments.local_port = 0;
    arguments.outbind_addr = NULL;
    arguments.outlocal_port = 0;
    arguments.type = FALSE;
    argp_parse(&argp, argc, argv, ARGP_NO_ARGS, 0, &arguments);
    printf("%s",notice);
    if ((server_sock = createListenerSocket(arguments.local_port)) < 0) { // start server
        printMessage("Cannot run server: %m");
        return server_sock;
    }

    signal(SIGCHLD, sigchld_handler); // prevent ended children from becoming zombies
    signal(SIGTERM, sigterm_handler); // handle KILL signal

    listenerLoop();
}

int check_ipversion(char * address)
{
/* Check for valid IPv4 or Iv6 string. Returns AF_INET for IPv4, AF_INET6 for IPv6 */

    struct in6_addr bindaddr;

    if (inet_pton(AF_INET, address, &bindaddr) == 1) {
         return AF_INET;
    } else {
        if (inet_pton(AF_INET6, address, &bindaddr) == 1) {
            return AF_INET6;
        }
    }
    return 0;
}

int createListenerSocket(int port){
    int server_sock, optval = 1;
    int validfamily=0;
    struct addrinfo hints, *res=NULL;
    char *portstr=NULL;
    portstr = (char*)malloc(12*sizeof(char));
    if (portstr == NULL){
        printMessage("invalid port pointer");
        exit(INVALID_POINTER);
    }
    memset(&hints, 0x00, sizeof(hints));
    server_sock = -1;

    hints.ai_flags    = AI_NUMERICSERV;   /* numeric service number, not resolve */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    /* prepare to bind on specified numeric address */
    if (arguments.bind_addr != NULL) {
        /* check for numeric IP to specify IPv6 or IPv4 socket */
        if ((validfamily = check_ipversion(arguments.bind_addr))) {
             hints.ai_family = validfamily;
             hints.ai_flags |= AI_NUMERICHOST; /* bind_addr is a valid numeric ip, skip resolve */
        }
    } else {
        /* if bind_address is NULL, will bind to IPv6 wildcard */
        hints.ai_family = AF_INET; /* Specify IPv6 socket, also allow ipv4 clients */
        hints.ai_flags |= AI_PASSIVE; /* Wildcard address */
    }

    sprintf(portstr, "%d", port);

    /* Check if specified socket is valid. Try to resolve address if bind_address is a hostname */
    if (getaddrinfo(arguments.bind_addr, portstr, &hints, &res) != 0) {
        return CLIENT_RESOLVE_ERROR;
    }

    if ((server_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
        freeaddrinfo(res); // Free memory on failure
        return SERVER_SOCKET_ERROR;
    }

    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        freeaddrinfo(res);
        return SERVER_SETSOCKOPT_ERROR;
    }

    if (bind(server_sock, res->ai_addr, res->ai_addrlen) == -1) {
        close(server_sock);
        freeaddrinfo(res);
        return SERVER_BIND_ERROR;
    }

    if (listen(server_sock, BACKLOG) < 0) {
        close(server_sock);
        freeaddrinfo(res);
        return SERVER_LISTEN_ERROR;
    }

    if (res != NULL) {
        freeaddrinfo(res);
    }
    if (portstr != NULL){
        free(portstr);
    }
    if (arguments.bind_addr != NULL){
        free(arguments.bind_addr);
    }
    return server_sock;
}

void printMessage(const char *format,...){
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr,format,ap);
    fprintf(stderr,"\n");
    va_end(ap);
}

/* Handle finished child process */
void sigchld_handler(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
    printf("%d",sig);
}

/* Handle term signal */
void sigterm_handler(int sig) {
    close(client_sock);
    close(server_sock);
    close(remote_socket);
    exit(sig);
}

void listenerLoop() {
    struct sockaddr_storage client_addr;
    socklen_t addrlen = sizeof(client_addr);

    while (TRUE) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addrlen);
        if (fork() == 0) { // handle client connection in a separate process
            close(server_sock);
            handle_client(client_sock);
            exit(0);
        } else {
            if (connections_processed < INT_MAX){
                connections_processed++;
            }else{
                printMessage("Data section overflowed");
                exit(DATA_SECTION_OVEFLOWED);
            }
        }
        close(client_sock);
    }
}

void handle_client(int client_sock)
{

    if (fork() == 0) { // a process forwarding(managing) data from client
        if (arguments.type == FALSE){
            //Blackhole portal
            forward_data(client_sock);
        }else if (arguments.type == TRUE){
            //Whitehole portal
            forward_data_w(client_sock);
        }
        exit(0);
    }

    closeSockets();

}

void closeSockets(){
    close(client_sock);
}

//Shuttle forwarding for blackhole
void forward_data(int source_sock) {
    ssize_t n;
    //size_t m;
    int count = 0;
    char *buffer = NULL;
    buffer = (char*)malloc(BUF_SIZE*sizeof(char));
    char *firstAnswer = NULL;
    char* secondAnswer = NULL;
    char* continueAnswer = NULL;
    char* dataAnswer = NULL;
    char* firstsReponse = NULL;
    char* secondResponse = NULL;
    char* thirdResponse = NULL;
    const int faSize = 32;
    const int saSize = 27;
    const int caSize = 8;
    const int daSize = 5;
    const int dsSize = 12;
    int frSize, srSize, trSize = 0;
    firstAnswer = (char*)malloc(faSize*sizeof(char));
    memcpy(firstAnswer,"220 portal ESMTP Service Ready\r\n",faSize);
    secondAnswer = (char*)malloc(saSize*sizeof(char));
    memcpy(secondAnswer,"250 portal greets shuttle\r\n",saSize);
    continueAnswer = (char*)malloc(caSize*sizeof(char));
    memcpy(continueAnswer,"250 OK\r\n",caSize);
    dataAnswer = (char*)malloc(daSize*sizeof(char));
    memcpy(dataAnswer,"354\r\n",daSize);
    char *bufferInput = NULL;
    bufferInput = (char*)malloc(BUF_SIZE*sizeof(char));
    char *destination = NULL;
    destination = (char*)malloc(dsSize*sizeof(char));
    memcpy(destination,"destination@",dsSize);
    char* domainDestination = NULL;
    if (bufferInput == NULL){
        printMessage("invalid buffer input pointer");
        exit(INVALID_POINTER);
    }
    if (buffer == NULL){
        printMessage("invalid buffer pointer");
        exit(INVALID_POINTER);
    }
    if (firstAnswer == NULL){
        printMessage("invalid buffer pointer");
        exit(INVALID_POINTER);
    }
    if (secondAnswer == NULL){
        printMessage("invalid buffer pointer");
        exit(INVALID_POINTER);
    }
    if (continueAnswer == NULL){
        printMessage("invalid buffer pointer");
        exit(INVALID_POINTER);
    }
    if (dataAnswer == NULL){
        printMessage("invalid buffer pointer");
        exit(INVALID_POINTER);
    }
    if (destination == NULL){
        printMessage("invalid buffer pointer");
        exit(INVALID_POINTER);
    }

    while(1){
        if (count == 0){
            fwrite(firstAnswer,1,faSize,stdout);
            if (write(source_sock, firstAnswer, faSize) < 0) {
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
            }
            n = read(source_sock, bufferInput, BUF_SIZE);
            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            }
            frSize = n;
            firstsReponse = (char*)malloc(frSize*sizeof(char));
            memcpy(firstsReponse,bufferInput,frSize);
            fwrite(firstsReponse,1,frSize,stdout);
            count = count+1;
        }else if(count == 1){
            fwrite(secondAnswer,1,saSize,stdout);
            if (write(source_sock, secondAnswer, saSize) < 0) {
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
            }
            n = read(source_sock, bufferInput, BUF_SIZE);
            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            }
            srSize = n;
            secondResponse = (char*)malloc(srSize*sizeof(char));
            memcpy(secondResponse,bufferInput,srSize);
            fwrite(secondResponse,1,srSize,stdout);
            count = count+1;
        }else if (count == 2){
            fwrite(continueAnswer,1,caSize,stdout);
            if (write(source_sock, continueAnswer, caSize) < 0) {
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
            }
            n = read(source_sock, bufferInput, BUF_SIZE);
            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            }
            trSize = n;
            thirdResponse = (char*)malloc(trSize*sizeof(char));
            memcpy(thirdResponse,bufferInput,trSize);
            fwrite(thirdResponse,1,trSize,stdout);
            count = count+1;
            break;
        }
    }
    if(searchDomain(thirdResponse)){
        printMessage("domain not found");
        exit(INVALID_POINTER);
    }
    remote_socket = connect_to_remote(arguments.outbind_addr, arguments.outlocal_port);
    if (remote_socket <= 0){
        printMessage("remote connection failed");
        exit(CLIENT_RESOLVE_ERROR);
    }
    while(1){
        n = read(remote_socket, buffer, BUF_SIZE);
        if (n < 0) {         // error in the "read" system call
            printMessage("read");
            exit(SOCKET_READ_ERROR);
        }
        if(strncmp(buffer, "output:",7) == 0){
            domainDestination = (char*)malloc((domainSize+dsSize+1)*sizeof(char));
            if (domainDestination == NULL){
                printMessage("invalid buffer pointer");
                exit(INVALID_POINTER);
            }
            memcpy(domainDestination, destination,dsSize);
            memcpy(domainDestination+dsSize,domain, domainSize);
            memcpy(domainDestination+dsSize+domainSize, ">", 1);
            fwrite(domainDestination,1,(domainSize+dsSize+1),stdout);
            if (write(remote_socket, domainDestination, (domainSize+dsSize+1)) < 0) {
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
            }
        }
        if(strncmp(buffer, "ready:",6) == 0){
            break;
        }
    }
    count = 0;
    while(1){
        if (count == 0){
            fwrite(firstsReponse,1,frSize,stdout);
            if (write(remote_socket, firstsReponse, frSize) < 0) {
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
            }
            count = count +1;
        }else if (count == 1){
            n = read(remote_socket, buffer, BUF_SIZE);
            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            }
            if(strncmp(buffer, "next:",5) == 0){
                fwrite(secondResponse,1,srSize,stdout);
                if (write(remote_socket, secondResponse, srSize) < 0) {
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
                }
                count = count +1;
            }
        } else if (count == 2){
            n = read(remote_socket, buffer, BUF_SIZE);
            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            }
            if(strncmp(buffer, "next:",5) == 0){
                fwrite(thirdResponse,1,trSize,stdout);
                if (write(remote_socket, thirdResponse, trSize) < 0) {
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
                }
                break;
            }
        }
    }
    fd_set fds_wormhole;
    FD_ZERO(&fds_wormhole);// initialize the set
    count = 0;
    n=0;
    while(1){
        FD_SET(source_sock, &fds_wormhole);  // monitor the client socket
        FD_SET(remote_socket, &fds_wormhole);   // monitor the remote socket
        // the select system call will return when one of the file
        // descriptors that it is monitoring is ready for an I/O operation
        if (select(FD_SETSIZE, &fds_wormhole, NULL, NULL, NULL) < 0) {
            printMessage("select");
            break;
        }
        // if new data arrives from client to remote
        if (FD_ISSET(source_sock, &fds_wormhole)) {
            count = read(source_sock, bufferInput, BUF_SIZE);

            if (count < 0) {          // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            } else if (count == 0) {  // receives 0 bytes
                break;
            }
            fwrite(bufferInput,1,count,stdout);
            if (write(remote_socket, bufferInput, count) < 0) {
                printMessage("write");
                exit(WRITE_SOCKET_ERROR);
            }
        }
        // if new data arrives from remote to client
        if (FD_ISSET(remote_socket, &fds_wormhole)) {
            n = read(remote_socket, bufferInput, BUF_SIZE);

            if (n < 0) {          // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            } else if (n == 0) {  // receives 0 bytes
                break;
            }
            fwrite(bufferInput,1,n,stdout);
            if (write(source_sock, bufferInput, n) < 0) {
                printMessage("write");
                exit(WRITE_SOCKET_ERROR);
            }
        }
    }
    printf("close socket\n");
    if (buffer != NULL){
        free(buffer);
    }
    if (bufferInput != NULL){
        free(bufferInput);
    }
    if (firstAnswer != NULL){
        free(firstAnswer );
    }
    if (secondAnswer != NULL){
        free(secondAnswer);
    }
    if (continueAnswer != NULL){
        free(continueAnswer);
    }
    if (dataAnswer != NULL){
        free(dataAnswer);
    }
    if (firstsReponse != NULL){
        free(firstsReponse);
    }
    if (secondResponse != NULL){
        free(secondResponse);
    }
    if (thirdResponse != NULL){
        free(thirdResponse);
    }
    if (domain != NULL){
        free(domain);
    }
    if (destination != NULL){
        free(destination);
    }
    if (domainDestination != NULL){
        free(domainDestination);
    }
    shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
    close(source_sock);
    close(remote_socket);
}

//Shuttle forwarding for whitehole
void forward_data_w(int source_sock){
    ssize_t n;
    //size_t m;
    int count = 0;
    int frSize = 0;
    int srSize = 0;
    int trSize = 0;
    int ftrSize = 0;
    int rwSize = 0;
    const int faSize = 7;
    const int saSize = 6;
    const int caSize = 5;
    char *bufferInput = NULL;
    char *buffer = NULL;
    char* continueAnswer = NULL;
    char* firstsReponse = NULL;
    char* secondReponse = NULL;
    char* thirdResponse = NULL;
    char* forthResponse = NULL;
    char *firstAnswer = NULL;
    char* secondAnswer = NULL;
    char* remoteWelcome = NULL;
    bufferInput = (char*)malloc(BUF_SIZE*sizeof(char));
    buffer = (char*)malloc(BUF_SIZE*sizeof(char));
    firstAnswer = (char*)malloc(faSize*sizeof(char));
    memcpy(firstAnswer,"output:",faSize);
    secondAnswer = (char*)malloc(saSize*sizeof(char));
    memcpy(secondAnswer,"ready:",saSize);
    continueAnswer = (char*)malloc(caSize*sizeof(char));
    memcpy(continueAnswer,"next:",caSize);

    if (bufferInput == NULL){
        printMessage("invalid buffer pointer");
        exit(INVALID_POINTER);
    }
    if (buffer == NULL){
        printMessage("invalid buffer pointer");
        exit(INVALID_POINTER);
    }
    if (firstAnswer == NULL){
        printMessage("invalid buffer pointer");
        exit(INVALID_POINTER);
    }
    if (secondAnswer == NULL){
        printMessage("invalid buffer pointer");
        exit(INVALID_POINTER);
    }
    if (continueAnswer == NULL){
        printMessage("invalid buffer pointer");
        exit(INVALID_POINTER);
    }

    while(1){
        if (count == 0){
            fwrite(firstAnswer,1,faSize,stdout);
            if (write(source_sock, firstAnswer, faSize) < 0) {
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
            }
            n = read(source_sock, bufferInput, BUF_SIZE);
            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            }
            frSize = n;
            firstsReponse = (char*)malloc(frSize*sizeof(char));
            memcpy(firstsReponse,bufferInput,frSize);
            fwrite(firstsReponse,1,frSize,stdout);
            break;
        }
    }

    if(searchDomain(firstsReponse)){
        printMessage("domain not found");
        exit(INVALID_POINTER);
    }
    char* mx = NULL;
    mx = get_mx_record(domain);
    if (!mx){
        printMessage("MX records not found");
        exit(CLIENT_RESOLVE_ERROR);
    }

    remote_socket = connect_to_remote(mx, arguments.outlocal_port);
    if (remote_socket <= 0){
        printMessage("remote connection failed");
        exit(CLIENT_RESOLVE_ERROR);
    }

    count = 0;
    while(1){
        if (count == 0){
            n = read(remote_socket, buffer, BUF_SIZE); // read 220 from remote
            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            }
            rwSize = n;
            remoteWelcome = (char*)malloc(rwSize*sizeof(char));
            memcpy(remoteWelcome,buffer,rwSize);
            fwrite(remoteWelcome,1,rwSize,stdout);
            if (write(source_sock, secondAnswer, saSize) < 0) { //write ready to client
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
            }
            count = count +1;
        }else if (count ==1 ){
            n = read(source_sock, bufferInput, BUF_SIZE); // read first answer from client
            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            }
            srSize = n;
            secondReponse = (char*)malloc(srSize*sizeof(char));
            memcpy(secondReponse,bufferInput,srSize);
            fwrite(secondReponse,1,srSize,stdout);
            if (write(remote_socket, secondReponse, srSize) < 0) { //write client name to remote
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
            }
            count = count +1;
        }else if (count == 2){
            n = read(remote_socket, buffer, BUF_SIZE); // read function and extensions from remote
            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            }
            fwrite(buffer,1,n,stdout);
            buffer[n] = '\0';
            if(memmem(buffer, n, "250 ", strlen("250 ")) != NULL){
                if (write(source_sock, continueAnswer, caSize) < 0) { //write next to client
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
                }
                count = count +1;
            }
        }else if (count == 3){
            n = read(source_sock, bufferInput, BUF_SIZE); // read MAIL FROM from client
            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            }
            trSize = n;
            thirdResponse = (char*)malloc(trSize*sizeof(char));
            memcpy(thirdResponse,bufferInput,trSize);
            fwrite(thirdResponse,1,trSize,stdout);
            if (write(remote_socket, thirdResponse, trSize) < 0) { //write MAIL FROM to remote
                printMessage("write");
                exit(WRITE_SOCKET_ERROR);
            }
            count = count +1;
        }else if (count == 4){
            n = read(remote_socket, buffer, BUF_SIZE); // read 250 OK from remote
            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            }
            buffer[n] = '\0';
            if(memmem(buffer, n, "250 ", strlen("250 ")) != NULL){
                if (write(source_sock, continueAnswer, caSize) < 0) { //write next to client
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
                }
                count = count +1;
            }
        }else if (count == 5){
            n = read(source_sock, bufferInput, BUF_SIZE); // read RCPT FROM from client
            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            }
            ftrSize = n;
            forthResponse = (char*)malloc(ftrSize*sizeof(char));
            memcpy(forthResponse,bufferInput,ftrSize);
            fwrite(forthResponse,1,ftrSize,stdout);
            if (write(remote_socket, forthResponse, ftrSize) < 0) { //write RCPT FROM to remote
                printMessage("write");
                exit(WRITE_SOCKET_ERROR);
            }
            break;
        }
    }

    fd_set fds_wormhole;
    FD_ZERO(&fds_wormhole);// initialize the set
    count = 0;
    n=0;
    while(1){
        FD_SET(source_sock, &fds_wormhole);  // monitor the client socket
        FD_SET(remote_socket, &fds_wormhole);   // monitor the remote socket
        // the select system call will return when one of the file
        // descriptors that it is monitoring is ready for an I/O operation
        if (select(FD_SETSIZE, &fds_wormhole, NULL, NULL, NULL) < 0) {
            printMessage("select");
            break;
        }
        // if new data arrives from client to remote
        if (FD_ISSET(source_sock, &fds_wormhole)) {
            count = read(source_sock, bufferInput, BUF_SIZE);

            if (count < 0) {          // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            } else if (count == 0) {  // receives 0 bytes
                break;
            }
            fwrite(bufferInput,1,count,stdout);
            if (write(remote_socket, bufferInput, count) < 0) {
                printMessage("write");
                exit(WRITE_SOCKET_ERROR);
            }
        }
        // if new data arrives from remote to client
        if (FD_ISSET(remote_socket, &fds_wormhole)) {
            n = read(remote_socket, bufferInput, BUF_SIZE);

            if (n < 0) {          // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            } else if (n == 0) {  // receives 0 bytes
                break;
            }
            fwrite(bufferInput,1,n,stdout);
            if (write(source_sock, bufferInput, n) < 0) {
                printMessage("write");
                exit(WRITE_SOCKET_ERROR);
            }
        }
    }

    printf("close socket\n");
    if (bufferInput != NULL){
        free(bufferInput);
    }
    if (buffer != NULL){
        free(buffer);
    }
    if (firstAnswer!= NULL){
        free(firstAnswer);
    }
    if (secondAnswer!= NULL){
        free(secondAnswer);
    }
    if (firstsReponse!= NULL){
        free(firstsReponse);
    }
    if (secondReponse!= NULL){
        free(secondReponse);
    }
    if (continueAnswer!= NULL){
        free(continueAnswer);
    }
    if (thirdResponse!= NULL){
        free(thirdResponse);
    }
    if (forthResponse!= NULL){
        free(forthResponse);
    }
    if (mx != NULL){
        free(mx);
    }

    shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
    close(source_sock);
    close(remote_socket);
}

size_t convert_ssize_to_size(ssize_t value){
    if (value < 0) {
        // Handle negative value appropriately
        // Here, we choose to return 0, but this could be an error code or another handling mechanism
        return 0; // Or handle it as needed
    }
    return (size_t)value; // Safe to convert
}

int searchDomain(char* message){
    if(strncmp(message, "RCPT",4) == 0){
        char* at = strchr(message, '@');
        if (at){
            char* end = strchr(at, '>');
            if (end){
                domainSize = end - (at + 1);
                domain = (char*)malloc(domainSize*sizeof(char));
                memcpy(domain,at+1,domainSize);
                fwrite(domain,1,domainSize,stdout);
            }else {
                return 1;
            }
        }else {
            return 1;
        }
    }else if (strncmp(message, "destination",11) == 0){
      char* at = strchr(message, '@');
        if (at){
            char* end = strchr(at, '>');
            if (end){
                domainSize = end - (at + 1);
                domain = (char*)malloc((domainSize+1)*sizeof(char));
                memcpy(domain,at+1,domainSize);
                fwrite(domain,1,domainSize,stdout);
                domain[domainSize] = '\0';
            }else {
                return 1;
            }
        }else {
            return 1;
        }
    }else {
        return 1;
    }
    return 0;
}

int connect_to_remote(char *host, int port) {
    int sock = -1;
    struct addrinfo hints, *res, *p;
    char port_str[16];
    int status;

    // Prep indication structure
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;        // IPv4 only (tu peux mettre AF_UNSPEC pour IPv4+IPv6)
    hints.ai_socktype = SOCK_STREAM;  // TCP

    snprintf(port_str, sizeof(port_str), "%d", port);

    // resolve name or validate ip address
    if ((status = getaddrinfo(host, port_str, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    // try each address
    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0)
            continue;

        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0)
            break; // sucess

        close(sock);
        sock = -1;
    }

    freeaddrinfo(res); // free memory by getaddrinfo

    if (sock < 0) {
        perror("connect");
        return -1;
    }

    return sock;
}

char* get_mx_record(char* domain){
  size_t answer_size = 4096;
  unsigned char* answer = NULL;
  answer = malloc(answer_size);
  if (!answer){
    printMessage("malloc(answer)");
    return NULL;
  }

  int len = res_query(domain, C_IN, T_MX, answer, (int)answer_size);
  if (len < 0){
    printMessage("res_query");
    if (answer != NULL){
      free(answer);
      answer = NULL;
    }
    return NULL;
  }
  ns_msg msg;
  if (ns_initparse(answer, len, &msg) < 0){
    printMessage("ns_initparse");
    if (answer != NULL){
      free(answer);
      answer = NULL;
    }
    return NULL;
  }
  int count = ns_msg_count(msg, ns_s_an);
  if (count == 0){
    printMessage("No MX records found");
    if (answer != NULL){
      free(answer);
      answer = NULL;
    }
    return NULL;
  }
  int bestPref = 65535;
  char* bestHost = NULL;
  for (int i = 0; i < count; i++){
    ns_rr rr;
    if (ns_parserr(&msg, ns_s_an, i, &rr) != 0)
      continue;
    const unsigned char* rdata = ns_rr_rdata(rr);
    int pref = ns_get16(rdata);
    char* exchange = NULL;
    exchange = (char*)malloc((len+1)*sizeof(char));
    if (!exchange){
      printMessage("malloc(exchange)");
      if (answer != NULL){
        free(answer);
        answer = NULL;
      }
      return NULL;
    }

    if(dn_expand(answer, answer+len, rdata+2, exchange, (len+1)) < 0){
      if (answer != NULL){
       free(answer);
       answer = NULL;
      }
      if (exchange != NULL){
        free(exchange);
        exchange = NULL;
      }
      continue;
    }
    if (pref < bestPref){
      if (bestHost != NULL){
        free(bestHost);
        bestHost = NULL;
      }
      bestHost = strdup(exchange);
      if (!bestHost){
        printMessage("malloc(bestHost)");
        if (answer != NULL){
          free(answer);
          answer = NULL;
        }
        if (exchange != NULL){
          free(exchange);
          exchange = NULL;
        }
        return NULL;
      }

      bestPref = pref;
    }
    if (exchange != NULL){
      free(exchange);
      exchange = NULL;
    }

  }
  if (answer != NULL){
    free(answer);
    answer = NULL;
  }
  if (!bestHost){
    return NULL;
  }
  return bestHost;
}
