#ifndef LIBEFPIX_H_
#define LIBEFPIX_H_

#define LIBEFPIX_VERSION 3

#define LIBEFPIX_DEF static inline

#include <sodium.h>
#include <string.h>
#include <stdbool.h>

#define LIBEFPIX_CFG_ALIAS_SIZE 16
#define LIBEFPIX_CFG_TIMESTAMP_SIZE 8
#define LIBEFPIX_CFG_MESSAGE_SIZE 64
#define LIBEFPIX_CFG_POW_NONCE_SIZE 8

#define LIBEFPIX_CFG_UC_POW_ZEROS 2
#define LIBEFPIX_CFG_BC_POW_ZEROS 2

#define LIBEFPIX_VL_HASH_SIZE crypto_generichash_BYTES // 32
#define LIBEFPIX_VL_ENCRYPT_PK_SIZE crypto_box_PUBLICKEYBYTES
#define LIBEFPIX_VL_ENCRYPT_SK_SIZE crypto_box_SECRETKEYBYTES
#define LIBEFPIX_VL_SIGN_PK_SIZE crypto_sign_PUBLICKEYBYTES
#define LIBEFPIX_VL_SIGN_SK_SIZE crypto_sign_SECRETKEYBYTES
#define LIBEFPIX_VL_SIGNATURE_SIZE crypto_sign_BYTES
#define LIBEFPIX_VL_SEAL_OVERHEAD crypto_box_SEALBYTES

typedef enum {
    LIBEFPIX_PT_SUC = 0,
    LIBEFPIX_PT_AUC,
    LIBEFPIX_PT_SBC,
    LIBEFPIX_PT_ABC,
} LIBEFPIX_PacketType;

#define LIBEFPIX_PT_HEADER_SIZE 2

#define LIBEFPIX_UC_PAYLOAD_SEND_ALIAS_OFF (0)
#define LIBEFPIX_UC_PAYLOAD_RECV_ALIAS_OFF (LIBEFPIX_CFG_ALIAS_SIZE)
#define LIBEFPIX_UC_PAYLOAD_TIMESTAMP_OFF (LIBEFPIX_UC_PAYLOAD_RECV_ALIAS_OFF + LIBEFPIX_CFG_ALIAS_SIZE)
#define LIBEFPIX_UC_PAYLOAD_MESSAGE_OFF (LIBEFPIX_UC_PAYLOAD_TIMESTAMP_OFF + LIBEFPIX_CFG_TIMESTAMP_SIZE)
#define LIBEFPIX_UC_PAYLOAD_SIGNATURE_OFF (LIBEFPIX_UC_PAYLOAD_MESSAGE_OFF + LIBEFPIX_CFG_MESSAGE_SIZE)
#define LIBEFPIX_UC_CONTENT_SIZE (LIBEFPIX_CFG_ALIAS_SIZE + LIBEFPIX_CFG_ALIAS_SIZE + LIBEFPIX_CFG_TIMESTAMP_SIZE + LIBEFPIX_CFG_MESSAGE_SIZE)
#define LIBEFPIX_UC_PAYLOAD_SIZE (LIBEFPIX_UC_CONTENT_SIZE + LIBEFPIX_VL_SIGNATURE_SIZE)
#define LIBEFPIX_UC_SEALED_OFF (LIBEFPIX_PT_HEADER_SIZE)
#define LIBEFPIX_UC_SEALED_SIZE (LIBEFPIX_UC_PAYLOAD_SIZE + LIBEFPIX_VL_SEAL_OVERHEAD)
#define LIBEFPIX_UC_POW_NONCE_OFF (LIBEFPIX_PT_HEADER_SIZE + LIBEFPIX_UC_SEALED_SIZE)

#define LIBEFPIX_PACKET_SIZE (LIBEFPIX_PT_HEADER_SIZE + LIBEFPIX_UC_SEALED_SIZE + LIBEFPIX_CFG_POW_NONCE_SIZE)

#define LIBEFPIX_BC_ALIAS_OFF (LIBEFPIX_PT_HEADER_SIZE)
#define LIBEFPIX_BC_TIMESTAMP_OFF (LIBEFPIX_BC_ALIAS_OFF + LIBEFPIX_CFG_ALIAS_SIZE)
#define LIBEFPIX_BC_MESSAGE_OFF (LIBEFPIX_BC_TIMESTAMP_OFF + LIBEFPIX_CFG_TIMESTAMP_SIZE)
#define LIBEFPIX_BC_SIGNATURE_OFF (LIBEFPIX_BC_MESSAGE_OFF + LIBEFPIX_CFG_MESSAGE_SIZE)
#define LIBEFPIX_BC_SIGNED_LEN (LIBEFPIX_CFG_ALIAS_SIZE + LIBEFPIX_CFG_TIMESTAMP_SIZE + LIBEFPIX_CFG_MESSAGE_SIZE)
#define LIBEFPIX_BC_PADDING_OFF (LIBEFPIX_BC_SIGNATURE_OFF + LIBEFPIX_VL_SIGNATURE_SIZE)
#define LIBEFPIX_BC_PADDING_SIZE (LIBEFPIX_UC_SEALED_SIZE - LIBEFPIX_CFG_ALIAS_SIZE - LIBEFPIX_CFG_TIMESTAMP_SIZE - LIBEFPIX_CFG_MESSAGE_SIZE - LIBEFPIX_VL_SIGNATURE_SIZE)

typedef struct {
    uint8_t encrypt_pk[LIBEFPIX_VL_ENCRYPT_PK_SIZE];
    uint8_t encrypt_sk[LIBEFPIX_VL_ENCRYPT_SK_SIZE];
    uint8_t sign_pk[LIBEFPIX_VL_SIGN_PK_SIZE];
    uint8_t sign_sk[LIBEFPIX_VL_SIGN_SK_SIZE];
} LIBEFPIX_Identity;

typedef struct {
    uint8_t their_alias[LIBEFPIX_CFG_ALIAS_SIZE];
    uint8_t my_alias[LIBEFPIX_CFG_ALIAS_SIZE];
    uint8_t encrypt_pk[LIBEFPIX_VL_ENCRYPT_PK_SIZE];
    uint8_t sign_pk[LIBEFPIX_VL_SIGN_PK_SIZE];
} LIBEFPIX_Contact;

typedef struct {
    LIBEFPIX_PacketType packet_type;
    uint8_t recv_alias[LIBEFPIX_CFG_ALIAS_SIZE];
    uint8_t message[LIBEFPIX_CFG_MESSAGE_SIZE];
} LIBEFPIX_Send;

typedef struct {
    LIBEFPIX_PacketType packet_type;
    uint8_t send_alias[LIBEFPIX_CFG_ALIAS_SIZE];
    uint8_t recv_alias[LIBEFPIX_CFG_ALIAS_SIZE];
    uint8_t send_timestamp[LIBEFPIX_CFG_TIMESTAMP_SIZE];
    uint8_t recv_timestamp[LIBEFPIX_CFG_TIMESTAMP_SIZE];
    uint8_t message[LIBEFPIX_CFG_MESSAGE_SIZE];
} LIBEFPIX_Recv;

LIBEFPIX_DEF bool LIBEFPIX__verify_pow(uint8_t* hash, uint8_t pow_zeros);
LIBEFPIX_DEF bool LIBEFPIX__check_and_relay(
        uint8_t pow_zeros,
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        bool (*relay)(uint8_t[LIBEFPIX_PACKET_SIZE])
    );

LIBEFPIX_DEF bool LIBEFPIX_init();
LIBEFPIX_DEF void LIBEFPIX_generate_identity(LIBEFPIX_Identity* identity);
LIBEFPIX_DEF bool LIBEFPIX_create_packet(
        LIBEFPIX_Send* send,
        LIBEFPIX_Identity* my_identity,
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        bool (*relay)(uint8_t[LIBEFPIX_PACKET_SIZE])
    );
LIBEFPIX_DEF bool LIBEFPIX_handle_packet(
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        LIBEFPIX_Identity* my_identity,
        LIBEFPIX_Recv* recv,
        bool (*relay)(uint8_t[LIBEFPIX_PACKET_SIZE])
    );
LIBEFPIX_DEF bool LIBEFPIX_no_recv_handle_packet(
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        bool (*relay)(uint8_t[LIBEFPIX_PACKET_SIZE])
    );

#ifdef LIBEFPIX_IMPLEMENTATION

#ifndef LIBEFPIX_CUSTOM

#include <time.h>

#ifndef LIBEFPIX_HASH_STORE_SIZE
#define LIBEFPIX_HASH_STORE_SIZE 100
#endif
#ifndef LIBEFPIX_CONTACT_STORE_SIZE
#define LIBEFPIX_CONTACT_STORE_SIZE 100
#endif
#ifndef LIBEFPIX_CFG_MAX_AGE
#define LIBEFPIX_CFG_MAX_AGE 5
#endif

static uint8_t LIBEFPIX__hash_store[LIBEFPIX_HASH_STORE_SIZE][LIBEFPIX_VL_HASH_SIZE];
static size_t LIBEFPIX__hash_store_count = 0;
static LIBEFPIX_Contact LIBEFPIX__contact_store[LIBEFPIX_CONTACT_STORE_SIZE];
static size_t LIBEFPIX__contact_store_count = 0;

static inline bool LIBEFPIX__check_hash(uint8_t dedup_hash[LIBEFPIX_VL_HASH_SIZE]) {
    for (size_t i = 0; i < LIBEFPIX__hash_store_count; i++) if (memcmp(LIBEFPIX__hash_store[i], dedup_hash, LIBEFPIX_VL_HASH_SIZE) == 0) return false;
    if (LIBEFPIX__hash_store_count < LIBEFPIX_HASH_STORE_SIZE) memcpy(LIBEFPIX__hash_store[LIBEFPIX__hash_store_count++], dedup_hash, LIBEFPIX_VL_HASH_SIZE);
    return true;
}
static inline bool LIBEFPIX__get_contact_from_alias(uint8_t alias[LIBEFPIX_CFG_ALIAS_SIZE], LIBEFPIX_Contact* contact) {
    for (size_t i = 0; i < LIBEFPIX__contact_store_count; i++) if (memcmp(LIBEFPIX__contact_store[i].their_alias, alias, LIBEFPIX_CFG_ALIAS_SIZE) == 0) {memcpy(contact, &LIBEFPIX__contact_store[i], sizeof(LIBEFPIX_Contact)); return true;}
    return false;
}
static inline void LIBEFPIX__get_timestamp(uint8_t timestamp[LIBEFPIX_CFG_TIMESTAMP_SIZE]) {
    uint64_t now = (uint64_t)time(NULL);
    memcpy(timestamp, &now, LIBEFPIX_CFG_TIMESTAMP_SIZE);
}
static inline bool LIBEFPIX__check_age(uint8_t recv_time[LIBEFPIX_CFG_TIMESTAMP_SIZE], uint8_t send_time[LIBEFPIX_CFG_TIMESTAMP_SIZE]) {
    uint64_t recv_ts, send_ts;
    memcpy(&recv_ts, recv_time, LIBEFPIX_CFG_TIMESTAMP_SIZE);
    memcpy(&send_ts, send_time, LIBEFPIX_CFG_TIMESTAMP_SIZE);
    if (recv_ts >= send_ts) return (uint32_t)(recv_ts - send_ts) < LIBEFPIX_CFG_MAX_AGE;
    else return false;
}

static inline void LIBEFPIX_add_contact(uint8_t their_alias[LIBEFPIX_CFG_ALIAS_SIZE], uint8_t my_alias[LIBEFPIX_CFG_ALIAS_SIZE], uint8_t encrypt_pk[LIBEFPIX_VL_ENCRYPT_PK_SIZE], uint8_t sign_pk[LIBEFPIX_VL_SIGN_PK_SIZE]) {
    if (LIBEFPIX__contact_store_count < LIBEFPIX_CONTACT_STORE_SIZE) {
        memcpy(LIBEFPIX__contact_store[LIBEFPIX__contact_store_count].their_alias, their_alias, LIBEFPIX_CFG_ALIAS_SIZE);
        memcpy(LIBEFPIX__contact_store[LIBEFPIX__contact_store_count].my_alias, my_alias, LIBEFPIX_CFG_ALIAS_SIZE);
        memcpy(LIBEFPIX__contact_store[LIBEFPIX__contact_store_count].encrypt_pk, encrypt_pk, LIBEFPIX_VL_ENCRYPT_PK_SIZE);
        memcpy(LIBEFPIX__contact_store[LIBEFPIX__contact_store_count].sign_pk, sign_pk, LIBEFPIX_VL_SIGN_PK_SIZE);
        ++LIBEFPIX__contact_store_count;
    }
}

#endif

LIBEFPIX_DEF bool LIBEFPIX__verify_pow(uint8_t* hash, uint8_t pow_zeros) {
    for (size_t i = 0; i < pow_zeros; ++i) if (hash[i] != 0) return false;
    return true;
}

LIBEFPIX_DEF bool LIBEFPIX__check_and_relay(
        uint8_t pow_zeros,
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        bool (*relay)(uint8_t[LIBEFPIX_PACKET_SIZE])
    ) {
    uint8_t pow_hash[LIBEFPIX_VL_HASH_SIZE];
    uint8_t dedup_hash[LIBEFPIX_VL_HASH_SIZE];
    crypto_generichash(pow_hash, LIBEFPIX_VL_HASH_SIZE, packet + 2, LIBEFPIX_UC_SEALED_SIZE + LIBEFPIX_CFG_POW_NONCE_SIZE, NULL, 0);
    if (!LIBEFPIX__verify_pow(pow_hash, pow_zeros)) return false;
    crypto_generichash(dedup_hash, LIBEFPIX_VL_HASH_SIZE, packet + 2, LIBEFPIX_UC_SEALED_SIZE, NULL, 0);
    if (!LIBEFPIX__check_hash(dedup_hash)) return false;
    relay(packet);
    return true;
}

LIBEFPIX_DEF bool LIBEFPIX_init(){
    return (sodium_init() >= 0);
}
LIBEFPIX_DEF void LIBEFPIX_generate_identity(LIBEFPIX_Identity* identity) {
    crypto_box_keypair(identity->encrypt_pk, identity->encrypt_sk);
    crypto_sign_keypair(identity->sign_pk, identity->sign_sk);
}

LIBEFPIX_DEF bool LIBEFPIX_create_packet(
        LIBEFPIX_Send* send,
        LIBEFPIX_Identity* my_identity,
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        bool (*relay)(uint8_t[LIBEFPIX_PACKET_SIZE])
    ) {
    packet[0] = LIBEFPIX_VERSION;
    packet[1] = send->packet_type;
    if (send->packet_type == LIBEFPIX_PT_SUC || send->packet_type == LIBEFPIX_PT_AUC) {
        uint8_t payload[LIBEFPIX_UC_PAYLOAD_SIZE];
        LIBEFPIX_Contact contact = {0};
        if (!LIBEFPIX__get_contact_from_alias(send->recv_alias, &contact)) return false;
        if (send->packet_type == LIBEFPIX_PT_SUC) {memcpy(payload + LIBEFPIX_UC_PAYLOAD_SEND_ALIAS_OFF, contact.my_alias, LIBEFPIX_CFG_ALIAS_SIZE); memcpy(payload + LIBEFPIX_UC_PAYLOAD_RECV_ALIAS_OFF, send->recv_alias, LIBEFPIX_CFG_ALIAS_SIZE);}
        else {memset(payload + LIBEFPIX_UC_PAYLOAD_SEND_ALIAS_OFF, 0, LIBEFPIX_CFG_ALIAS_SIZE); memset(payload + LIBEFPIX_UC_PAYLOAD_RECV_ALIAS_OFF, 0, LIBEFPIX_CFG_ALIAS_SIZE);}
        LIBEFPIX__get_timestamp(payload + LIBEFPIX_UC_PAYLOAD_TIMESTAMP_OFF);
        memcpy(payload + LIBEFPIX_UC_PAYLOAD_MESSAGE_OFF, send->message, LIBEFPIX_CFG_MESSAGE_SIZE);
        if (send->packet_type == LIBEFPIX_PT_SUC) crypto_sign_detached(payload + LIBEFPIX_UC_PAYLOAD_SIGNATURE_OFF, NULL, payload, LIBEFPIX_UC_CONTENT_SIZE, my_identity->sign_sk);
        else memset(payload + LIBEFPIX_UC_PAYLOAD_SIGNATURE_OFF, 0, LIBEFPIX_VL_SIGNATURE_SIZE);
        crypto_box_seal(packet + LIBEFPIX_UC_SEALED_OFF, payload, LIBEFPIX_UC_PAYLOAD_SIZE, contact.encrypt_pk);
    }
    else if (send->packet_type == LIBEFPIX_PT_SBC || send->packet_type == LIBEFPIX_PT_ABC) {
        LIBEFPIX_Contact contact = {0};
        if (!LIBEFPIX__get_contact_from_alias(send->recv_alias, &contact)) return false;
        if (send->packet_type == LIBEFPIX_PT_SBC) memcpy(packet + LIBEFPIX_BC_ALIAS_OFF, contact.my_alias, LIBEFPIX_CFG_ALIAS_SIZE);
        else memset(packet + LIBEFPIX_BC_ALIAS_OFF, 0, LIBEFPIX_CFG_ALIAS_SIZE);
        LIBEFPIX__get_timestamp(packet + LIBEFPIX_BC_TIMESTAMP_OFF);
        memcpy(packet + LIBEFPIX_BC_MESSAGE_OFF, send->message, LIBEFPIX_CFG_MESSAGE_SIZE);
        if (send->packet_type == LIBEFPIX_PT_SBC) crypto_sign_detached(packet + LIBEFPIX_BC_SIGNATURE_OFF, NULL, packet + LIBEFPIX_PT_HEADER_SIZE, LIBEFPIX_BC_SIGNED_LEN, my_identity->sign_sk);
        else memset(packet + LIBEFPIX_BC_SIGNATURE_OFF, 0, LIBEFPIX_VL_SIGNATURE_SIZE);
        randombytes_buf(packet + LIBEFPIX_BC_PADDING_OFF, LIBEFPIX_BC_PADDING_SIZE);
    }
    else return false;
    uint8_t pow_zeros = 0;
    if (send->packet_type == LIBEFPIX_PT_SUC || send->packet_type == LIBEFPIX_PT_AUC) pow_zeros = LIBEFPIX_CFG_UC_POW_ZEROS;
    else if (send->packet_type == LIBEFPIX_PT_SBC || send->packet_type == LIBEFPIX_PT_ABC) pow_zeros = LIBEFPIX_CFG_BC_POW_ZEROS;
    else return false;
    uint8_t pow_hash[LIBEFPIX_VL_HASH_SIZE];
    do {
        randombytes_buf(packet + LIBEFPIX_UC_POW_NONCE_OFF, LIBEFPIX_CFG_POW_NONCE_SIZE);
        crypto_generichash(pow_hash, LIBEFPIX_VL_HASH_SIZE, packet + LIBEFPIX_PT_HEADER_SIZE, LIBEFPIX_PACKET_SIZE - LIBEFPIX_PT_HEADER_SIZE, NULL, 0);
    } while (!LIBEFPIX__verify_pow(pow_hash, pow_zeros));
    return LIBEFPIX__check_and_relay(pow_zeros, packet, relay);
}

LIBEFPIX_DEF bool LIBEFPIX_handle_packet(
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        LIBEFPIX_Identity* my_identity,
        LIBEFPIX_Recv* recv,
        bool (*relay)(uint8_t[LIBEFPIX_PACKET_SIZE])
    ) {
    if (packet[0] != LIBEFPIX_VERSION) return false;
    recv->packet_type = packet[1];
    uint8_t pow_zeros = 0;
    if (recv->packet_type == LIBEFPIX_PT_SUC || recv->packet_type == LIBEFPIX_PT_AUC) pow_zeros = LIBEFPIX_CFG_UC_POW_ZEROS;
    else if (recv->packet_type == LIBEFPIX_PT_SBC || recv->packet_type == LIBEFPIX_PT_ABC) pow_zeros = LIBEFPIX_CFG_BC_POW_ZEROS;
    else return false;
    if (!LIBEFPIX__check_and_relay(pow_zeros, packet, relay)) return false;
    LIBEFPIX__get_timestamp(recv->recv_timestamp);
    if (recv->packet_type == LIBEFPIX_PT_SUC || recv->packet_type == LIBEFPIX_PT_AUC) {
        uint8_t payload[LIBEFPIX_UC_PAYLOAD_SIZE];
        if (crypto_box_seal_open(payload, packet + LIBEFPIX_UC_SEALED_OFF, LIBEFPIX_UC_SEALED_SIZE, my_identity->encrypt_pk, my_identity->encrypt_sk) != 0) return false;
        memcpy(recv->send_alias, payload + LIBEFPIX_UC_PAYLOAD_SEND_ALIAS_OFF, LIBEFPIX_CFG_ALIAS_SIZE);
        memcpy(recv->recv_alias, payload + LIBEFPIX_UC_PAYLOAD_RECV_ALIAS_OFF, LIBEFPIX_CFG_ALIAS_SIZE);
        memcpy(recv->send_timestamp, payload + LIBEFPIX_UC_PAYLOAD_TIMESTAMP_OFF, LIBEFPIX_CFG_TIMESTAMP_SIZE);
        memcpy(recv->message, payload + LIBEFPIX_UC_PAYLOAD_MESSAGE_OFF, LIBEFPIX_CFG_MESSAGE_SIZE);
        if (!LIBEFPIX__check_age(recv->recv_timestamp, recv->send_timestamp)) return false;
        if (recv->packet_type == LIBEFPIX_PT_SUC) {
            LIBEFPIX_Contact contact = {0};
            if (!LIBEFPIX__get_contact_from_alias(recv->send_alias, &contact)) return false;
            if (crypto_sign_verify_detached(payload + LIBEFPIX_UC_PAYLOAD_SIGNATURE_OFF, payload, LIBEFPIX_UC_CONTENT_SIZE, contact.sign_pk) != 0) return false;
        }
    }
    else if (recv->packet_type == LIBEFPIX_PT_SBC || recv->packet_type == LIBEFPIX_PT_ABC) {
        memcpy(recv->send_alias, packet + LIBEFPIX_BC_ALIAS_OFF, LIBEFPIX_CFG_ALIAS_SIZE);
        memset(recv->recv_alias, 0, LIBEFPIX_CFG_ALIAS_SIZE);
        memcpy(recv->send_timestamp, packet + LIBEFPIX_BC_TIMESTAMP_OFF, LIBEFPIX_CFG_TIMESTAMP_SIZE);
        memcpy(recv->message, packet + LIBEFPIX_BC_MESSAGE_OFF, LIBEFPIX_CFG_MESSAGE_SIZE);
        if (!LIBEFPIX__check_age(recv->recv_timestamp, recv->send_timestamp)) return false;
        if (recv->packet_type == LIBEFPIX_PT_SBC) {
            LIBEFPIX_Contact contact = {0};
            if (!LIBEFPIX__get_contact_from_alias(recv->send_alias, &contact)) return false;
            if (crypto_sign_verify_detached(packet + LIBEFPIX_BC_SIGNATURE_OFF, packet + LIBEFPIX_PT_HEADER_SIZE, LIBEFPIX_BC_SIGNED_LEN, contact.sign_pk) != 0) return false;
        }
    }
    else return false;
    return true;
}

LIBEFPIX_DEF bool LIBEFPIX_no_recv_handle_packet(
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        bool (*relay)(uint8_t[LIBEFPIX_PACKET_SIZE])
    ) {
    if (packet[0] != LIBEFPIX_VERSION) return false;
    uint8_t pow_zeros = 0;
    if (packet[1] == LIBEFPIX_PT_SUC || packet[1] == LIBEFPIX_PT_AUC) pow_zeros = LIBEFPIX_CFG_UC_POW_ZEROS;
    else if (packet[1] == LIBEFPIX_PT_SBC || packet[1] == LIBEFPIX_PT_ABC) pow_zeros = LIBEFPIX_CFG_BC_POW_ZEROS;
    else return false;
    return LIBEFPIX__check_and_relay(pow_zeros, packet, relay);
}

#endif // LIBEFPIX_IMPLEMENTATION

#endif // LIBEFPIX_H_

/*
LICENSE:
    MIT License

    Copyright (c) 2025 Arin Upadhyay

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/
