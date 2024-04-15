#pragma once

#include "exception.h"

#include <iomanip>
#include <map>
#include <string>

#include <winsock2.h>
#include <ws2tcpip.h>
 
#pragma comment(lib, "ws2_32.lib")

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


void check_command_line_arguments(int);

void wsa_startup(WSADATA &);

void create_socket(SOCKET &);

void set_socket_timeout(SOCKET, int, int);

void set_destination_address(SOCKADDR_IN&, char*);

void set_socket_routing(SOCKET);

void trace_route(SOCKET&, SOCKADDR_IN&);

void set_time_to_live(SOCKET, int);

void set_request_packet(char *, int, int);

USHORT calculate_check_sum(USHORT *, int);

int send_request_packet(SOCKET&, char*, int, SOCKADDR_IN&);

int receive_response_packet(SOCKET&, char*, int, SOCKADDR_IN&);

int parse_response_packet(char *, int, SOCKADDR_IN *, int);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// добавить флаги в командной строке
// добавить --help
