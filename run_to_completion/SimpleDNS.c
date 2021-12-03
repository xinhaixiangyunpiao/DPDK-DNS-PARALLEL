#include "SimpleDNS.h"

int get_A_Record(uint8_t addr[4], const char domain_name[]){
    if (strcmp("foo.bar.com", domain_name) == 0){
        addr[0] = 192;
        addr[1] = 168;
        addr[2] = 1;
        addr[3] = 1;
        return 0;
    }else{
        return -1;
    }
}

int get_AAAA_Record(uint8_t addr[16], const char domain_name[]){
    if (strcmp("foo.bar.com", domain_name) == 0){
        addr[0] = 0xfe;
        addr[1] = 0x80;
        addr[2] = 0x00;
        addr[3] = 0x00;
        addr[4] = 0x00;
        addr[5] = 0x00;
        addr[6] = 0x00;
        addr[7] = 0x00;
        addr[8] = 0x00;
        addr[9] = 0x00;
        addr[10] = 0x00;
        addr[11] = 0x00;
        addr[12] = 0x00;
        addr[13] = 0x00;
        addr[14] = 0x00;
        addr[15] = 0x01;
        return 0;
    }else{
        return -1;
    }
}

void print_hex(uint8_t* buf, size_t len){
    int i;
    printf("%zu bytes:\n", len);
    for(i = 0; i < len; ++i)
        printf("%02x ", buf[i]);
    printf("\n");
}

void print_resource_record(struct ResourceRecord* rr){
    int i;
    while (rr){
        printf("  ResourceRecord { name '%s', type %u, class %u, ttl %u, rd_length %u, ",
            rr->name,
            rr->type,
            rr->class,
            rr->ttl,
            rr->rd_length
        );

        union ResourceData *rd = &rr->rd_data;
        switch (rr->type){
            case A_Resource_RecordType:
                printf("Address Resource Record { address ");
                for(i = 0; i < 4; ++i)
                printf("%s%u", (i ? "." : ""), rd->a_record.addr[i]);
                printf(" }");
                break;
            case NS_Resource_RecordType:
                printf("Name Server Resource Record { name %s }",
                rd->name_server_record.name
            );
                break;
            case CNAME_Resource_RecordType:
                printf("Canonical Name Resource Record { name %u }",
                rd->cname_record.name
            );
                break;
            case SOA_Resource_RecordType:
                printf("SOA { MName '%s', RName '%s', serial %u, refresh %u, retry %u, expire %u, minimum %u }",
                rd->soa_record.MName,
                rd->soa_record.RName,
                rd->soa_record.serial,
                rd->soa_record.refresh,
                rd->soa_record.retry,
                rd->soa_record.expire,
                rd->soa_record.minimum
            );
                break;
            case PTR_Resource_RecordType:
                printf("Pointer Resource Record { name '%s' }",
                rd->ptr_record.name
            );
                break;
            case MX_Resource_RecordType:
                printf("Mail Exchange Record { preference %u, exchange '%s' }",
                rd->mx_record.preference,
                rd->mx_record.exchange
            );
                break;
            case TXT_Resource_RecordType:
                printf("Text Resource Record { txt_data '%s' }",
                rd->txt_record.txt_data
            );
                break;
            case AAAA_Resource_RecordType:
                printf("AAAA Resource Record { address ");
                for(i = 0; i < 16; ++i)
                printf("%s%02x", (i ? ":" : ""), rd->aaaa_record.addr[i]);
                printf(" }");
                break;
            default:
                printf("Unknown Resource Record { ??? }");
        }
        printf("}\n");
        rr = rr->next;
    }
}

void print_query(struct Message* msg){
    printf("QUERY { ID: %02x", msg->id);
    printf(". FIELDS: [ QR: %u, OpCode: %u ]", msg->qr, msg->opcode);
    printf(", QDcount: %u", msg->qdCount);
    printf(", ANcount: %u", msg->anCount);
    printf(", NScount: %u", msg->nsCount);
    printf(", ARcount: %u,\n", msg->arCount);
    struct Question* q = msg->questions;
    while (q){
        printf("  Question { qName '%s', qType %u, qClass %u }\n",
        q->qName,
        q->qType,
        q->qClass
        );
        q = q->next;
    }
    print_resource_record(msg->answers);
    print_resource_record(msg->authorities);
    print_resource_record(msg->additionals);
    printf("}\n");
}

size_t get16bits(const uint8_t** buffer){
    uint16_t value;
    memcpy(&value, *buffer, 2);
    *buffer += 2;
    return ntohs(value);
}

void put8bits(uint8_t** buffer, uint8_t value){
    memcpy(*buffer, &value, 1);
    *buffer += 1;
}

void put16bits(uint8_t** buffer, uint16_t value){
    value = htons(value);
    memcpy(*buffer, &value, 2);
    *buffer += 2;
}

void put32bits(uint8_t** buffer, uint32_t value){
    value = htons(value);
    memcpy(*buffer, &value, 4);
    *buffer += 4;
}

// 3foo3bar3com0 => foo.bar.com (No full validation is done!)
char *decode_domain_name(const uint8_t **buf, size_t len){
    char domain[256];
    for (int i = 1; i < MIN(256, len); i += 1) {
        uint8_t c = (*buf)[i];
        if (c == 0) {
            domain[i - 1] = 0;
            *buf += i + 1;
            return strdup(domain);
        } else if (c <= 63) {
            domain[i - 1] = '.';
        } else {
            domain[i - 1] = c;
        }
    }
    return NULL;
}

// foo.bar.com => 3foo3bar3com0
void encode_domain_name(uint8_t** buffer, const char* domain){
    uint8_t* buf = *buffer;
    const char* beg = domain;
    const char* pos;
    int len = 0;
    int i = 0;
    while ((pos = strchr(beg, '.'))){
        len = pos - beg;
        buf[i] = len;
        i += 1;
        memcpy(buf+i, beg, len);
        i += len;
        beg = pos + 1;
    }
    len = strlen(domain) - (beg - domain);
    buf[i] = len;
    i += 1;
    memcpy(buf + i, beg, len);
    i += len;
    buf[i] = 0;
    i += 1;
    *buffer += i;
}

void decode_header(struct Message* msg, const uint8_t** buffer){
    msg->id = get16bits(buffer);
    uint32_t fields = get16bits(buffer);
    msg->qr = (fields & QR_MASK) >> 15;
    msg->opcode = (fields & OPCODE_MASK) >> 11;
    msg->aa = (fields & AA_MASK) >> 10;
    msg->tc = (fields & TC_MASK) >> 9;
    msg->rd = (fields & RD_MASK) >> 8;
    msg->ra = (fields & RA_MASK) >> 7;
    msg->rcode = (fields & RCODE_MASK) >> 0;
    msg->qdCount = get16bits(buffer);
    msg->anCount = get16bits(buffer);
    msg->nsCount = get16bits(buffer);
    msg->arCount = get16bits(buffer);
}

void encode_header(struct Message* msg, uint8_t** buffer){
    put16bits(buffer, msg->id);
    int fields = 0;
    fields |= (msg->qr << 15) & QR_MASK;
    fields |= (msg->rcode << 0) & RCODE_MASK;
    // TODO: insert the rest of the fields
    put16bits(buffer, fields);
    put16bits(buffer, msg->qdCount);
    put16bits(buffer, msg->anCount);
    put16bits(buffer, msg->nsCount);
    put16bits(buffer, msg->arCount);
}

int decode_msg(struct Message* msg, const uint8_t* buffer, int size){
    int i;
    decode_header(msg, &buffer);
    if (msg->anCount != 0 || msg->nsCount != 0){
        printf("Only questions expected!\n");
        return -1;
    }
    // parse questions
    uint32_t qcount = msg->qdCount;
    struct Question* qs = msg->questions;
    for (i = 0; i < qcount; ++i){
        struct Question* q = malloc(sizeof(struct Question));
        q->qName = decode_domain_name(&buffer, size);
        q->qType = get16bits(&buffer);
        q->qClass = get16bits(&buffer);
        // prepend question to questions list
        q->next = qs;
        msg->questions = q;
    }
    // We do not expect any resource records to parse here.
    return 0;
}

// For every question in the message add a appropiate resource record
// in either section 'answers', 'authorities' or 'additionals'.
void resolver_process(struct Message* msg){
    struct ResourceRecord* beg;
    struct ResourceRecord* rr;
    struct Question* q;
    int rc;

    // leave most values intact for response
    msg->qr = 1; // this is a response
    msg->aa = 1; // this server is authoritative
    msg->ra = 0; // no recursion available
    msg->rcode = Ok_ResponseType;

    // should already be 0
    msg->anCount = 0;
    msg->nsCount = 0;
    msg->arCount = 0;

    // for every question append resource records
    q = msg->questions;
    while (q){
        rr = malloc(sizeof(struct ResourceRecord));
        memset(rr, 0, sizeof(struct ResourceRecord));
        rr->name = strdup(q->qName);
        rr->type = q->qType;
        rr->class = q->qClass;
        rr->ttl = 60*60; // in seconds; 0 means no caching
        // printf("Query for '%s'\n", q->qName);
        // We only can only answer two question types so far
        // and the answer (resource records) will be all put
        // into the answers list.
        // This behavior is probably non-standard!
        switch (q->qType){
            case A_Resource_RecordType:
                rr->rd_length = 4;
                rc = get_A_Record(rr->rd_data.a_record.addr, q->qName);
                if (rc < 0){
                    free(rr->name);
                    free(rr);
                    goto next;
                }
                break;
            case AAAA_Resource_RecordType:
                rr->rd_length = 16;
                rc = get_AAAA_Record(rr->rd_data.aaaa_record.addr, q->qName);
                if (rc < 0){
                    free(rr->name);
                    free(rr);
                    goto next;
                }
                break;
            /*
            case NS_Resource_RecordType:
            case CNAME_Resource_RecordType:
            case SOA_Resource_RecordType:
            case PTR_Resource_RecordType:
            case MX_Resource_RecordType:
            case TXT_Resource_RecordType:
            */
            default:
                free(rr);
                msg->rcode = NotImplemented_ResponseType;
                printf("Cannot answer question of type %d.\n", q->qType);
                goto next;
        }
        msg->anCount++;
        // prepend resource record to answers list
        beg = msg->answers;
        msg->answers = rr;
        rr->next = beg;
        // jump here to omit question
        next:
        // process next question
        q = q->next;
    }
}

/* @return 0 upon failure, 1 upon success */
int encode_resource_records(struct ResourceRecord* rr, uint8_t** buffer){
    int i;
    while (rr){
        // Answer questions by attaching resource sections.
        encode_domain_name(buffer, rr->name);
        put16bits(buffer, rr->type);
        put16bits(buffer, rr->class);
        put32bits(buffer, rr->ttl);
        put16bits(buffer, rr->rd_length);
        switch (rr->type){
            case A_Resource_RecordType:
                for(i = 0; i < 4; ++i)
                    put8bits(buffer, rr->rd_data.a_record.addr[i]);
                break;
            case AAAA_Resource_RecordType:
                for(i = 0; i < 16; ++i)
                    put8bits(buffer, rr->rd_data.aaaa_record.addr[i]);
                break;
            default:
                fprintf(stderr, "Unknown type %u. => Ignore resource record.\n", rr->type);
            return 1;
        }
        rr = rr->next;
    }
    return 0;
}

/* @return 0 upon failure, 1 upon success */
int encode_msg(struct Message* msg, uint8_t** buffer){
    struct Question* q;
    int rc;
    encode_header(msg, buffer);
    q = msg->questions;
    while (q){
        encode_domain_name(buffer, q->qName);
        put16bits(buffer, q->qType);
        put16bits(buffer, q->qClass);
        q = q->next;
    }
    rc = 0;
    rc |= encode_resource_records(msg->answers, buffer);
    rc |= encode_resource_records(msg->authorities, buffer);
    rc |= encode_resource_records(msg->additionals, buffer);
    return rc;
}

void free_resource_records(struct ResourceRecord* rr){
    struct ResourceRecord* next;
    while (rr) {
        free(rr->name);
        next = rr->next;
        free(rr);
        rr = next;
    }
}

void free_questions(struct Question* qq){
    struct Question* next;
    while (qq) {
        free(qq->qName);
        next = qq->next;
        free(qq);
        qq = next;
    }
}
