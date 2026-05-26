/*
A lightweight C implementation of the EFPIX protocol (https://github.com/shinymonitor/EFPIX)

USAGE:
    #define LIBEFPIX_IMPLEMENTATION  // STB style
    #include "libefpix.h"

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


#ifndef LIBEFPIX_H_
#define LIBEFPIX_H_

#define LIBEFPIX_VERSION 2

#define LIBEFPIX_DEF static inline

#include <string.h>
#include <stdbool.h>
#include <sodium.h>

#define LIBEFPIX_ALIAS_SIZE 16
#define LIBEFPIX_TIMESTAMP_SIZE 8
#define LIBEFPIX_MESSAGE_SIZE 256
#define LIBEFPIX_POW_NONCE_SIZE 8
#define LIBEFPIX_POW_ZEROS 2
#define LIBEFPIX_MAX_AGE 1

#define LIBEFPIX_HASH_SIZE crypto_generichash_BYTES // 32

#define LIBEFPIX_ENC_PK_SIZE crypto_box_PUBLICKEYBYTES
#define LIBEFPIX_ENC_SK_SIZE crypto_box_SECRETKEYBYTES
#define LIBEFPIX_SIGN_PK_SIZE crypto_sign_PUBLICKEYBYTES
#define LIBEFPIX_SIGN_SK_SIZE crypto_sign_SECRETKEYBYTES
#define LIBEFPIX_SIG_SIZE crypto_sign_BYTES
#define LIBEFPIX_SEAL_OVERHEAD crypto_box_SEALBYTES

#define LIBEFPIX_UNICAST 0
#define LIBEFPIX_SIGNED_BROADCAST 1
#define LIBEFPIX_ANON_BROADCAST 2

#define LIBEFPIX_PACKAGE_SIZE (LIBEFPIX_ALIAS_SIZE + LIBEFPIX_TIMESTAMP_SIZE + LIBEFPIX_MESSAGE_SIZE + LIBEFPIX_SIG_SIZE) // = 344
#define LIBEFPIX_SEALED_SIZE (LIBEFPIX_PACKAGE_SIZE + LIBEFPIX_SEAL_OVERHEAD) // = 392
#define LIBEFPIX_PACKET_SIZE (2 + LIBEFPIX_SEALED_SIZE + LIBEFPIX_POW_NONCE_SIZE) // = 402

#define LIBEFPIX_BC_SIGNPK_OFF 2
#define LIBEFPIX_BC_TS_OFF (LIBEFPIX_BC_SIGNPK_OFF + LIBEFPIX_SIGN_PK_SIZE)
#define LIBEFPIX_BC_MSG_OFF (LIBEFPIX_BC_TS_OFF + LIBEFPIX_TIMESTAMP_SIZE)
#define LIBEFPIX_BC_SIG_OFF (LIBEFPIX_BC_MSG_OFF + LIBEFPIX_MESSAGE_SIZE)
#define LIBEFPIX_BC_PAD_OFF (LIBEFPIX_BC_SIG_OFF + LIBEFPIX_SIG_SIZE)
#define LIBEFPIX_BC_SIGNED_LEN (LIBEFPIX_TIMESTAMP_SIZE + LIBEFPIX_MESSAGE_SIZE)
#define LIBEFPIX_BC_PAD_SIZE (LIBEFPIX_SEALED_SIZE - LIBEFPIX_SIGN_PK_SIZE - LIBEFPIX_TIMESTAMP_SIZE - LIBEFPIX_MESSAGE_SIZE - LIBEFPIX_SIG_SIZE)

typedef struct {
    uint8_t encrypt_public_key[LIBEFPIX_ENC_PK_SIZE];
    uint8_t encrypt_secret_key[LIBEFPIX_ENC_SK_SIZE];
    uint8_t sign_public_key[LIBEFPIX_SIGN_PK_SIZE];
    uint8_t sign_secret_key[LIBEFPIX_SIGN_SK_SIZE];
} LIBEFPIX_Identity;

typedef struct {
    uint8_t alias[LIBEFPIX_ALIAS_SIZE];
    uint8_t send_timestamp[LIBEFPIX_TIMESTAMP_SIZE];
    uint8_t message[LIBEFPIX_MESSAGE_SIZE];
} LIBEFPIX_Send;

typedef struct {
    uint8_t their_alias[LIBEFPIX_ALIAS_SIZE];
    uint8_t my_alias[LIBEFPIX_ALIAS_SIZE];
    uint8_t encrypt_public_key[LIBEFPIX_ENC_PK_SIZE];
    uint8_t sign_public_key[LIBEFPIX_SIGN_PK_SIZE];
} LIBEFPIX_Contact;

typedef struct {
    bool    unknown;
    bool    broadcast;
    LIBEFPIX_Contact contact;
    uint8_t sender_alias[LIBEFPIX_ALIAS_SIZE];
    uint8_t send_timestamp[LIBEFPIX_TIMESTAMP_SIZE];
    uint8_t recv_timestamp[LIBEFPIX_TIMESTAMP_SIZE];
    uint8_t message[LIBEFPIX_MESSAGE_SIZE];
} LIBEFPIX_Recv;

LIBEFPIX_DEF bool libefpix_verify_pow(const uint8_t *hash);
LIBEFPIX_DEF bool libefpix_pow_and_dedup(
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        uint8_t out_dedup_hash[LIBEFPIX_HASH_SIZE],
        bool (*hash_check_and_relay)(uint8_t[LIBEFPIX_HASH_SIZE], uint8_t[LIBEFPIX_PACKET_SIZE])
    );
LIBEFPIX_DEF void LIBEFPIX_generate_identity(LIBEFPIX_Identity *identity);
LIBEFPIX_DEF void LIBEFPIX_encode(
        LIBEFPIX_Send *send,
        LIBEFPIX_Identity* identity,
        uint8_t receiver_encrypt_public_key[LIBEFPIX_ENC_PK_SIZE],
        bool anonymous, bool broadcast,
        uint8_t packet[LIBEFPIX_PACKET_SIZE]
    );
LIBEFPIX_DEF bool LIBEFPIX_decode(
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        LIBEFPIX_Identity* identity,
        LIBEFPIX_Recv* recv,
        bool (*hash_check_and_relay)(uint8_t[LIBEFPIX_HASH_SIZE], uint8_t[LIBEFPIX_PACKET_SIZE]),
        bool (*get_contact_from_alias)(uint8_t[LIBEFPIX_ALIAS_SIZE], LIBEFPIX_Contact*),
        void (*get_timestamp)(uint8_t[LIBEFPIX_TIMESTAMP_SIZE]),
        uint32_t (*get_age)(uint8_t[LIBEFPIX_TIMESTAMP_SIZE], uint8_t[LIBEFPIX_TIMESTAMP_SIZE])
    );
LIBEFPIX_DEF bool LIBEFPIX_no_recv(
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        bool (*hash_check_and_relay)(uint8_t[LIBEFPIX_HASH_SIZE], uint8_t[LIBEFPIX_PACKET_SIZE])
    );

#ifdef LIBEFPIX_IMPLEMENTATION

LIBEFPIX_DEF bool libefpix_verify_pow(const uint8_t *hash) {
    for (size_t i = 0; i < LIBEFPIX_POW_ZEROS; ++i)
        if (hash[i] != 0) return false;
    return true;
}

LIBEFPIX_DEF bool libefpix_pow_and_dedup(
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        uint8_t out_dedup_hash[LIBEFPIX_HASH_SIZE],
        bool (*hash_check_and_relay)(uint8_t[LIBEFPIX_HASH_SIZE], uint8_t[LIBEFPIX_PACKET_SIZE])
    ) {
    uint8_t pow_hash[LIBEFPIX_HASH_SIZE];
    crypto_generichash(pow_hash, LIBEFPIX_HASH_SIZE, packet + 2, LIBEFPIX_SEALED_SIZE + LIBEFPIX_POW_NONCE_SIZE, NULL, 0);
    if (!libefpix_verify_pow(pow_hash)) return false;
    crypto_generichash(out_dedup_hash, LIBEFPIX_HASH_SIZE, packet + 2, LIBEFPIX_SEALED_SIZE, NULL, 0);
    return hash_check_and_relay(out_dedup_hash, packet);
}

LIBEFPIX_DEF void LIBEFPIX_generate_identity(LIBEFPIX_Identity *identity) {
    crypto_box_keypair(identity->encrypt_public_key, identity->encrypt_secret_key);
    crypto_sign_keypair(identity->sign_public_key,   identity->sign_secret_key);
}

LIBEFPIX_DEF void LIBEFPIX_encode(
        LIBEFPIX_Send *send,
        LIBEFPIX_Identity* identity,
        uint8_t receiver_encrypt_public_key[LIBEFPIX_ENC_PK_SIZE],
        bool anonymous, bool broadcast,
        uint8_t packet[LIBEFPIX_PACKET_SIZE]
    ) {
    uint8_t pow_hash[LIBEFPIX_HASH_SIZE];
    packet[0] = LIBEFPIX_VERSION;
    if (!broadcast) {
        packet[1] = LIBEFPIX_UNICAST;
        uint8_t package[LIBEFPIX_PACKAGE_SIZE];
        uint8_t* p_alias = package;
        uint8_t* p_ts = package + LIBEFPIX_ALIAS_SIZE;
        uint8_t* p_msg = package + LIBEFPIX_ALIAS_SIZE + LIBEFPIX_TIMESTAMP_SIZE;
        uint8_t* p_sig = package + LIBEFPIX_ALIAS_SIZE + LIBEFPIX_TIMESTAMP_SIZE + LIBEFPIX_MESSAGE_SIZE;
        if (anonymous) memset(p_alias, 0, LIBEFPIX_ALIAS_SIZE);
        else memcpy(p_alias, send->alias, LIBEFPIX_ALIAS_SIZE);
        memcpy(p_ts,  send->send_timestamp, LIBEFPIX_TIMESTAMP_SIZE);
        memcpy(p_msg, send->message, LIBEFPIX_MESSAGE_SIZE);
        if (anonymous) memset(p_sig, 0, LIBEFPIX_SIG_SIZE);
        else crypto_sign_detached(p_sig, NULL, package, LIBEFPIX_ALIAS_SIZE + LIBEFPIX_TIMESTAMP_SIZE + LIBEFPIX_MESSAGE_SIZE, identity->sign_secret_key);
        crypto_box_seal(packet + 2, package, LIBEFPIX_PACKAGE_SIZE, receiver_encrypt_public_key);
    }
    else {
        packet[1] = anonymous ? LIBEFPIX_ANON_BROADCAST : LIBEFPIX_SIGNED_BROADCAST;
        if (anonymous) memset(packet + LIBEFPIX_BC_SIGNPK_OFF, 0, LIBEFPIX_SIGN_PK_SIZE);
        else memcpy(packet + LIBEFPIX_BC_SIGNPK_OFF, identity->sign_public_key, LIBEFPIX_SIGN_PK_SIZE);
        memcpy(packet + LIBEFPIX_BC_TS_OFF, send->send_timestamp, LIBEFPIX_TIMESTAMP_SIZE);
        memcpy(packet + LIBEFPIX_BC_MSG_OFF, send->message, LIBEFPIX_MESSAGE_SIZE);
        if (anonymous) memset(packet + LIBEFPIX_BC_SIG_OFF, 0, LIBEFPIX_SIG_SIZE);
        else crypto_sign_detached(packet + LIBEFPIX_BC_SIG_OFF, NULL, packet + LIBEFPIX_BC_TS_OFF, LIBEFPIX_BC_SIGNED_LEN, identity->sign_secret_key);
        randombytes_buf(packet + LIBEFPIX_BC_PAD_OFF, LIBEFPIX_BC_PAD_SIZE);
    }
    do {
        randombytes_buf(packet + 2 + LIBEFPIX_SEALED_SIZE, LIBEFPIX_POW_NONCE_SIZE);
        crypto_generichash(pow_hash, LIBEFPIX_HASH_SIZE, packet + 2, LIBEFPIX_SEALED_SIZE + LIBEFPIX_POW_NONCE_SIZE, NULL, 0);
    } while (!libefpix_verify_pow(pow_hash));
}

LIBEFPIX_DEF bool LIBEFPIX_decode(
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        LIBEFPIX_Identity* identity,
        LIBEFPIX_Recv* recv,
        bool (*hash_check_and_relay)(uint8_t[LIBEFPIX_HASH_SIZE], uint8_t[LIBEFPIX_PACKET_SIZE]),
        bool (*get_contact_from_alias)(uint8_t[LIBEFPIX_ALIAS_SIZE], LIBEFPIX_Contact*),
        void (*get_timestamp)(uint8_t[LIBEFPIX_TIMESTAMP_SIZE]),
        uint32_t (*get_age)(uint8_t[LIBEFPIX_TIMESTAMP_SIZE], uint8_t[LIBEFPIX_TIMESTAMP_SIZE])
    ) {
    uint8_t hash[LIBEFPIX_HASH_SIZE];
    if (packet[0] != LIBEFPIX_VERSION) return false;
    if (!libefpix_pow_and_dedup(packet, hash, hash_check_and_relay)) return false;
    get_timestamp(recv->recv_timestamp);
    recv->broadcast = (packet[1] != LIBEFPIX_UNICAST);
    if (packet[1] == LIBEFPIX_UNICAST) {
        uint8_t package[LIBEFPIX_PACKAGE_SIZE];
        if (crypto_box_seal_open(package, packet + 2, LIBEFPIX_SEALED_SIZE, identity->encrypt_public_key, identity->encrypt_secret_key) != 0) return false;
        const uint8_t *p_alias = package;
        const uint8_t *p_ts = package + LIBEFPIX_ALIAS_SIZE;
        const uint8_t *p_msg = package + LIBEFPIX_ALIAS_SIZE + LIBEFPIX_TIMESTAMP_SIZE;
        const uint8_t *p_sig = package + LIBEFPIX_ALIAS_SIZE + LIBEFPIX_TIMESTAMP_SIZE + LIBEFPIX_MESSAGE_SIZE;
        memcpy(recv->send_timestamp, p_ts,  LIBEFPIX_TIMESTAMP_SIZE);
        memcpy(recv->message,        p_msg, LIBEFPIX_MESSAGE_SIZE);
        if (get_age(recv->recv_timestamp, recv->send_timestamp) > LIBEFPIX_MAX_AGE) return false;
        static const uint8_t zero_alias[LIBEFPIX_ALIAS_SIZE] = {0};
        if (sodium_memcmp(p_alias, zero_alias, LIBEFPIX_ALIAS_SIZE) == 0) {
            memset(recv->sender_alias, 0, LIBEFPIX_ALIAS_SIZE);
            recv->unknown = true;
            return true;
        }
        memcpy(recv->sender_alias, p_alias, LIBEFPIX_ALIAS_SIZE);
        if (!get_contact_from_alias(recv->sender_alias, &recv->contact)) {
            recv->unknown = true;
            return true;
        }
        if (crypto_sign_verify_detached(p_sig, package, LIBEFPIX_ALIAS_SIZE + LIBEFPIX_TIMESTAMP_SIZE + LIBEFPIX_MESSAGE_SIZE, recv->contact.sign_public_key) != 0) return false;
        recv->unknown = false;
        return true;
    }
    else {
        const uint8_t *sign_pk = packet + LIBEFPIX_BC_SIGNPK_OFF;
        const uint8_t *ts = packet + LIBEFPIX_BC_TS_OFF;
        const uint8_t *msg = packet + LIBEFPIX_BC_MSG_OFF;
        const uint8_t *sig = packet + LIBEFPIX_BC_SIG_OFF;
        memset(recv->sender_alias, 0, LIBEFPIX_ALIAS_SIZE);
        memcpy(recv->send_timestamp, ts,  LIBEFPIX_TIMESTAMP_SIZE);
        memcpy(recv->message, msg, LIBEFPIX_MESSAGE_SIZE);
        if (packet[1] == LIBEFPIX_SIGNED_BROADCAST) {
            if (crypto_sign_verify_detached(sig, ts, LIBEFPIX_BC_SIGNED_LEN, sign_pk) != 0) return false;
            memcpy(recv->contact.sign_public_key, sign_pk, LIBEFPIX_SIGN_PK_SIZE);
            recv->unknown = false;
        }
        else recv->unknown = true;
        return true;
    }
}

LIBEFPIX_DEF bool LIBEFPIX_no_recv(
        uint8_t packet[LIBEFPIX_PACKET_SIZE],
        bool (*hash_check_and_relay)(uint8_t[LIBEFPIX_HASH_SIZE], uint8_t[LIBEFPIX_PACKET_SIZE])
    ) {
    uint8_t hash[LIBEFPIX_HASH_SIZE];
    if (packet[0] != LIBEFPIX_VERSION) return false;
    return libefpix_pow_and_dedup(packet, hash, hash_check_and_relay);
}

#endif // LIBEFPIX_IMPLEMENTATION

#endif // LIBEFPIX_H_
