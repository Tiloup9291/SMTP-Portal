## Description
SMTP Portal

The executable Portal of SMTP Portal is a process server or client that operate over the TCP layer of the OSI model in command line.
The Portal will output debug data receive through the sockets stripped from the bottom OSI layer header to STDOUT.
The Portal act as a couple of proxies chaining. You must start a process on a remote computer acting has the whitehole (output).
You must also start a process on a local computer acting has the blackhole (input).
Both processes (blackhole and whitehole) will share data between the wormhole.
The SMTP client connect to the blackhole, the blackhole connect to the whitehole and the whitehole reach the MX/MTA server.
The executable gives you the possibility to bind to an IPv4 or IPv6 address, if none is specify, it will bind to ANY.
You can also specify the port you wish to connect the process.
You have access to an help option and a usage option.
Finally, you can output the license.

The source used the most of the standard libraries, ANSI C compatible. 
## Installation

Here how to build main.c with gcc (developped with gcc v14.1.1):
```
gcc -Wall -flto -O2 -Wextra -Wall -Wpedantic -D_FORTIFY_SOURCE=2 -fdata-sections -ffunction-sections -Wl,-z,relro,-z,now -fsanitize=address -fPIE -pie -fstack-protector-strong -fcf-protection=full -mshstk  -c /path/to/main.c -o path/to/store/main.o
gcc  -o path/to/store/Portal path/to/get/main.o  -O2 -flto -s -lresolv
```
Alternately, you can use the Makefile. Here are the available flags and their initial value :
```
CC=gcc
CFLAGS=-O2 -flto -s -lresolv
LDFLAGS=-Wall -flto -O2 -Wextra -Wall -Wpedantic -D_FORTIFY_SOURCE=2 -fdata-sections -ffunction-sections -Wl,-z,relro,-z,now -fsanitize=address -fPIE -pie -fstack-protector-strong -fcf-protection=full -mshstk
PREFIX = /usr
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin
```
To build the object file and executable :
```
make or make all or make build or make Portal
```
To install (copy) the executable in a common binaries folder :
```
make install
```
To remove the object file :
```
make clean
```
## Usage

Example of usage:
Case of remote MTA server, with remote whitehole, local blackhole and local SMTP client.
We are using postfix. Be sure to set the /etc/postfix/main.cf setting : relayhost= to the address of the blackhole. (ex. : relayhosts = [127.0.0.3]:25);
1. Start the whitehole:
```
./Portal -b 192.168.1.25 -l 1002 -j 25 -t w
```
2. Start the blackhole :
```
./Portal -b 127.0.0.3 -l 25 -c 192.168.2.35 -j 1002 -t b
```
3. Send an email :
```
echo "Test" | mail -s "Test" yourAdress@yourDomain.tld
```
4. Postfix 127.0.0.1:25 will connect to the black hole on 127.0.0.3:25, the blackhole will output on 192.168.2.35:1002. The whitehole will receive data from 192.168.1.25:1002 and output to MTA server on the resolved MX address:25.
5. Both CLI will output debug message during processing.
6. You should receive your mail in your mail box.
