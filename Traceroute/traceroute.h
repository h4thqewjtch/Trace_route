#include <iostream>
#include <iomanip>
#include <map>

#include <winsock2.h>
#include <ws2tcpip.h>
 
#include <stdio.h>
#include <stdlib.h>
 
#pragma comment(lib, "ws2_32.lib")


std::map<UCHAR, std::string> icmpMessageTypesMap{
    {0, "ECHO REPLY"},
    {3, "DESTINATION UNREACHABLE"},
    {4, "SOURCE QUENCH"},
    {5, "REDIRECT"},
    {6, "ALTERNATIVE HOST ADDRESS"},
    {8, "ECHO"},
    {9, "ROUTER ADVERTISEMENT"},
    {10, "ROUTER SOLICITATION"},
    {11, "TIME EXCEEDED"},
    {12, "PARAMETER PROBLEM"},
    {13, "TIMESTAMP"},
    {14, "TIMESTAMP REPLY"}};

std::map<UCHAR, std::string> icmpMessageCodesMap{
    {0, "NET UNREACHABLE"},
    {1, "HOST UNREACHABLE"},
    {2, "PROTOCOL QUENCH"},
    {3, "PORT UNREACHABLE"},
    {4, "FRAGMENTATION NEEDED"},
    {5, "SOURCE ROUTE FAILED"},
    {6, "DESTINATION NETWORK UNKNOWN"},
    {7, "DESTINATION HOST UNKNOWN"},
    {8, "SOURCE HOST ISOLATED"},
    {9, "COMMUNICATION WITH DESTINATION NETWORK IS ADMINISTRATIVELY PROHIBITED"},
    {10, "COMMUNICATION WITH DESTINATION HOST IS ADMINISTRATIVELY PROHIBITED"},
    {11, "DESTINATION NETWORK UNREACHABLE FOR TYPE OF SERVICE"},
    {12, "DESTINATION HOST UNREACHABLE FOR TYPE OF SERVICE"},
    {13, "COMMUNICATION ADMINISTRATIVELY PROHIBITED"},
    {14, "HOST PRECEDENCE VIOLATION"},
    {15, "PRECEDENCE CUTOFF IN EFFECT"}};


struct ICMPHeader
{
    UCHAR messageType;      // 8 bits
    UCHAR messageCode;      // 8 bits
    USHORT messageCheckSum; // 16 bits
    USHORT identificator;   // 16 bits
    USHORT sequenceNumber;  // 16 bits
};

struct IPHeader
{
    UINT headerLength : 4;              // 4 bits
    UINT ipVersion : 4;                 // 4 bits
    UCHAR typeOfService;                // 8 bits
    USHORT totalPacketLength;           // 16 bits
    USHORT identification;              // 16 bits
    USHORT flagsAndFragmantationOffset; // 3 bits (flags) and 13 bits(fragmentation offset)
    UCHAR timeToLive;                   // 8 bits
    UCHAR protocol;                     // 8 bits
    USHORT headerCheckSum;              // 16 bits
    UINT sourceIPAddress;               // 32 bits
    UINT destinationIPAddress;          // 32 bits
};


int check_command_line_arguments(int);

int wsa_startup(WSADATA &);

int get_nodes_number(int, char **);

int create_socket(SOCKET &);

int set_socket_timeout(SOCKET, int, int);

int set_destination_address(SOCKADDR_IN&, char*);

int set_socket_routing(SOCKET);

int trace_route(SOCKET&, SOCKADDR_IN&, int);

int set_time_to_live(SOCKET, int);

void set_send_buffer(char *, int, int);

USHORT calculate_check_sum(USHORT *, int);

int send_packet(SOCKET&, char*, int, SOCKADDR_IN&);

int receive_packet(SOCKET&, char*, int, SOCKADDR_IN&);

int parse_response(char *, int, SOCKADDR_IN *, int);

void print_host_name_addr(hostent*, SOCKADDR_IN*);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// добавить исключения
// добачить флаги в командной строке
// добавить  --help
