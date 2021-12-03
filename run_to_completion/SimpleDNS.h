#ifndef _SIMPLEDNS_H_
#define _SIMPLEDNS_H_

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#define BUF_SIZE 1500
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

/*
* Masks and constants.
*/
static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x8000;
static const uint32_t RCODE_MASK = 0x000F;

/* Response Type */
enum {
    Ok_ResponseType = 0,
    FormatError_ResponseType = 1,
    ServerFailure_ResponseType = 2,
    NameError_ResponseType = 3,
    NotImplemented_ResponseType = 4,
    Refused_ResponseType = 5
};

/* Resource Record Types */
enum {
    A_Resource_RecordType = 1,
    NS_Resource_RecordType = 2,
    CNAME_Resource_RecordType = 5,
    SOA_Resource_RecordType = 6,
    PTR_Resource_RecordType = 12,
    MX_Resource_RecordType = 15,
    TXT_Resource_RecordType = 16,
    AAAA_Resource_RecordType = 28,
    SRV_Resource_RecordType = 33
};

/* Operation Code */
enum {
    QUERY_OperationCode = 0, /* standard query */
    IQUERY_OperationCode = 1, /* inverse query */
    STATUS_OperationCode = 2, /* server status request */
    NOTIFY_OperationCode = 4, /* request zone transfer */
    UPDATE_OperationCode = 5 /* change resource records */
};

/* Response Code */
enum {
    NoError_ResponseCode = 0,
    FormatError_ResponseCode = 1,
    ServerFailure_ResponseCode = 2,
    NameError_ResponseCode = 3
};

/* Query Type */
enum {
    IXFR_QueryType = 251,
    AXFR_QueryType = 252,
    MAILB_QueryType = 253,
    MAILA_QueryType = 254,
    STAR_QueryType = 255
};

/* Question Section */
struct Question {
  char *qName;
  uint16_t qType;
  uint16_t qClass;
  struct Question* next; // for linked list
};

/* Data part of a Resource Record */
union ResourceData {
    struct {
        char *txt_data;
    } txt_record;
    struct {
        uint8_t addr[4];
    } a_record;
    struct {
        char* MName;
        char* RName;
        uint32_t serial;
        uint32_t refresh;
        uint32_t retry;
        uint32_t expire;
        uint32_t minimum;
    } soa_record;
    struct {
        char *name;
    } name_server_record;
    struct {
        char name;
    } cname_record;
    struct {
        char *name;
    } ptr_record;
    struct {
        uint16_t preference;
        char *exchange;
    } mx_record;
    struct {
        uint8_t addr[16];
    } aaaa_record;
    struct {
        uint16_t priority;
        uint16_t weight;
        uint16_t port;
        char *target;
    } srv_record;
};

/* Resource Record Section */
struct ResourceRecord {
    char *name;
    uint16_t type;
    uint16_t class;
    uint16_t ttl;
    uint16_t rd_length;
    union ResourceData rd_data;
    struct ResourceRecord* next; // for linked list
};

struct Message {
    uint16_t id; /* Identifier */
    /* Flags */
    uint16_t qr; /* Query/Response Flag */
    uint16_t opcode; /* Operation Code */
    uint16_t aa; /* Authoritative Answer Flag */
    uint16_t tc; /* Truncation Flag */
    uint16_t rd; /* Recursion Desired */
    uint16_t ra; /* Recursion Available */
    uint16_t rcode; /* Response Code */
    uint16_t qdCount; /* Question Count */
    uint16_t anCount; /* Answer Record Count */
    uint16_t nsCount; /* Authority Record Count */
    uint16_t arCount; /* Additional Record Count */
    /* At least one question; questions are copied to the response 1:1 */
    struct Question* questions;
    /*
    * Resource records to be send back.
    * Every resource record can be in any of the following places.
    * But every place has a different semantic.
    */
    struct ResourceRecord* answers;
    struct ResourceRecord* authorities;
    struct ResourceRecord* additionals;
};

int get_A_Record(uint8_t addr[4], const char domain_name[]);

int get_AAAA_Record(uint8_t addr[16], const char domain_name[]);

void print_hex(uint8_t* buf, size_t len);

void print_resource_record(struct ResourceRecord* rr);

void print_query(struct Message* msg);

size_t get16bits(const uint8_t** buffer);

void put8bits(uint8_t** buffer, uint8_t value);

void put16bits(uint8_t** buffer, uint16_t value);

void put32bits(uint8_t** buffer, uint32_t value);

char* decode_domain_name(const uint8_t **buf, size_t len);

void encode_domain_name(uint8_t** buffer, const char* domain);

void decode_header(struct Message* msg, const uint8_t** buffer);

void encode_header(struct Message* msg, uint8_t** buffer);

int decode_msg(struct Message* msg, const uint8_t* buffer, int size);

void resolver_process(struct Message* msg);

int encode_resource_records(struct ResourceRecord* rr, uint8_t** buffer);

int encode_msg(struct Message* msg, uint8_t** buffer);

void free_resource_records(struct ResourceRecord* rr);

void free_questions(struct Question* qq);

#endif