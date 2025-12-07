#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "../lib/monocypher.h"
#include "../lib/monocypher-ed25519.h"
//=====================HELPER PREPROCS=========================
#define LIBEFPIX_UNICAST 0
#define LIBEFPIX_SIGNED_BROADCAST 1
#define LIBEFPIX_ANON_BROADCAST 2
#define LIBEFPIX_PAYLOAD_SIZE (LIBEFPIX_ALIAS_SIZE+LIBEFPIX_TIMESTAMP_SIZE+LIBEFPIX_INTERNAL_ADDRESS_SIZE+LIBEFPIX_MESSAGE_SIZE)
#define LIBEFPIX_ENCRYPT_SIZE (LIBEFPIX_PAYLOAD_SIZE+64)
#define LIBEFPIX_PACKAGE_SIZE (LIBEFPIX_ENCRYPT_SIZE+32+24+16)
#define LIBEFPIX_BROADCAST_MESSAGE_SIZE (LIBEFPIX_PACKAGE_SIZE-LIBEFPIX_TIMESTAMP_SIZE-LIBEFPIX_INTERNAL_ADDRESS_SIZE-64-32)
#define LIBEFPIX_PACKET_SIZE  (LIBEFPIX_PACKAGE_SIZE+LIBEFPIX_POW_NONCE_SIZE+1+1)
//==========================TYPES===============================
typedef struct {
    uint8_t kx_public_key[32],
    kx_secret_key[32],
    sign_public_key[32],
    sign_secret_key[64];
} LIBEFPIX_Identity;
typedef struct {
    bool anonymous, broadcast;
    LIBEFPIX_Identity identity; uint8_t my_alias[LIBEFPIX_ALIAS_SIZE],
    receiver_kx_public_key[32],
    timestamp[LIBEFPIX_TIMESTAMP_SIZE],
    internal_address[LIBEFPIX_INTERNAL_ADDRESS_SIZE],
    message[LIBEFPIX_MESSAGE_SIZE], broadcast_message[LIBEFPIX_BROADCAST_MESSAGE_SIZE];
} LIBEFPIX_Send;
typedef struct {
    uint8_t their_alias[LIBEFPIX_ALIAS_SIZE],
    kx_public_key[32],
    sign_public_key[32],
    my_alias[LIBEFPIX_ALIAS_SIZE];
} LIBEFPIX_Contact;
typedef struct {
    bool unknown, broadcast;
    LIBEFPIX_Contact contact;
    uint8_t send_timestamp[LIBEFPIX_TIMESTAMP_SIZE],
    recv_timestamp[LIBEFPIX_TIMESTAMP_SIZE],
    internal_address[LIBEFPIX_INTERNAL_ADDRESS_SIZE],
    message[LIBEFPIX_MESSAGE_SIZE], broadcast_message[LIBEFPIX_BROADCAST_MESSAGE_SIZE];
} LIBEFPIX_Recv;
//====================USER VISIBLE FUNCTIONS====================
void LIBEFPIX_generate_identity(LIBEFPIX_Identity* identity);
void LIBEFPIX_encode(LIBEFPIX_Send send, uint8_t packet[LIBEFPIX_PACKET_SIZE]);
bool LIBEFPIX_decode(uint8_t packet[LIBEFPIX_PACKET_SIZE], LIBEFPIX_Identity identity, LIBEFPIX_Recv* recv,
    bool (*hash_check_and_relay)(uint8_t[LIBEFPIX_HASH_SIZE], uint8_t[LIBEFPIX_PACKET_SIZE]),
    bool (*get_contact_from_alias)(uint8_t[LIBEFPIX_ALIAS_SIZE], LIBEFPIX_Contact*),
    void (*get_timestamp)(uint8_t[LIBEFPIX_TIMESTAMP_SIZE]),
    uint32_t (*get_age)(uint8_t[LIBEFPIX_TIMESTAMP_SIZE], uint8_t[LIBEFPIX_TIMESTAMP_SIZE]));
//=============================PRNG============================
#include <sys/syscall.h>
#include <unistd.h>
static inline void get_random_bytes(uint8_t* buffer, size_t len) {
    syscall(SYS_getrandom, buffer, len, 0);
}
//=============================================================
static inline bool verify_pow(uint8_t hash[LIBEFPIX_HASH_SIZE]){
    for (size_t i=0; i<LIBEFPIX_POW_ZEROS; ++i) if (hash[i]!=0) return false;
    return true;
}
void LIBEFPIX_generate_identity(LIBEFPIX_Identity* identity) {
    uint8_t seed[32];
    get_random_bytes(seed, 32);
    crypto_ed25519_key_pair(identity->sign_secret_key, identity->sign_public_key, seed);
    crypto_wipe(seed, 32);
    get_random_bytes(identity->kx_secret_key, 32);
    crypto_x25519_public_key(identity->kx_public_key, identity->kx_secret_key);
}
void LIBEFPIX_encode(LIBEFPIX_Send send, uint8_t packet[LIBEFPIX_PACKET_SIZE]){
    uint8_t to_encrypt[LIBEFPIX_ENCRYPT_SIZE]={0};
    uint8_t ephemeral_pk[32], ephemeral_sk[32], shared_secret[32];
    uint8_t mac[16], nonce[24], cipher[LIBEFPIX_ENCRYPT_SIZE];
    uint8_t pow_hash[LIBEFPIX_HASH_SIZE];
    memset(packet, LIBEFPIX_VERSION, 1);
    if (!send.broadcast){
        if (send.anonymous) {memset(send.my_alias, 0, LIBEFPIX_ALIAS_SIZE);}
        memcpy(to_encrypt, send.my_alias, LIBEFPIX_ALIAS_SIZE);
        memcpy(to_encrypt+LIBEFPIX_ALIAS_SIZE, send.timestamp, LIBEFPIX_TIMESTAMP_SIZE);
        memcpy(to_encrypt+LIBEFPIX_ALIAS_SIZE+LIBEFPIX_TIMESTAMP_SIZE, send.internal_address, LIBEFPIX_INTERNAL_ADDRESS_SIZE);
        memcpy(to_encrypt+LIBEFPIX_ALIAS_SIZE+LIBEFPIX_TIMESTAMP_SIZE+LIBEFPIX_INTERNAL_ADDRESS_SIZE, send.message, LIBEFPIX_MESSAGE_SIZE);
        if (!send.anonymous) crypto_eddsa_sign(to_encrypt + LIBEFPIX_PAYLOAD_SIZE, send.identity.sign_secret_key, to_encrypt, LIBEFPIX_PAYLOAD_SIZE);
        get_random_bytes(ephemeral_sk, 32);
        crypto_x25519_public_key(ephemeral_pk, ephemeral_sk);
        crypto_x25519(shared_secret, ephemeral_sk, send.receiver_kx_public_key);
        get_random_bytes(nonce, 24);
        crypto_aead_lock(cipher, mac, shared_secret, nonce, NULL, 0, to_encrypt, LIBEFPIX_ENCRYPT_SIZE);
        memset(packet+1, LIBEFPIX_UNICAST, 1);
        memcpy(packet+1+1, mac, 16);
        memcpy(packet+1+1+16, nonce, 24);
        memcpy(packet+1+1+16+24, ephemeral_pk, 32);
        memcpy(packet+1+1+16+24+32, cipher, LIBEFPIX_ENCRYPT_SIZE);
        crypto_wipe(ephemeral_sk, 32);
        crypto_wipe(shared_secret, 32);
        crypto_wipe(to_encrypt, LIBEFPIX_ENCRYPT_SIZE);
    }
    else {
        if (send.anonymous) memset(packet+1, LIBEFPIX_ANON_BROADCAST, 1);
        else memset(packet+1, LIBEFPIX_SIGNED_BROADCAST, 1);
        if (!send.anonymous) memcpy(packet+1+1, send.identity.sign_public_key, 32);
        memcpy(packet+1+1+32, send.timestamp, LIBEFPIX_TIMESTAMP_SIZE);
        memcpy(packet+1+1+32+LIBEFPIX_TIMESTAMP_SIZE, send.internal_address, LIBEFPIX_INTERNAL_ADDRESS_SIZE);
        memcpy(packet+1+1+32+LIBEFPIX_TIMESTAMP_SIZE+LIBEFPIX_INTERNAL_ADDRESS_SIZE, send.broadcast_message, LIBEFPIX_BROADCAST_MESSAGE_SIZE);
        if (!send.anonymous) crypto_eddsa_sign(packet+1+1+32+LIBEFPIX_TIMESTAMP_SIZE+LIBEFPIX_INTERNAL_ADDRESS_SIZE+LIBEFPIX_BROADCAST_MESSAGE_SIZE, send.identity.sign_secret_key, packet+1+1+32, LIBEFPIX_BROADCAST_MESSAGE_SIZE+LIBEFPIX_TIMESTAMP_SIZE+LIBEFPIX_INTERNAL_ADDRESS_SIZE);
    }
    crypto_blake2b(pow_hash, LIBEFPIX_HASH_SIZE, packet+1+1, LIBEFPIX_PACKAGE_SIZE+LIBEFPIX_POW_NONCE_SIZE);
    while(!verify_pow(pow_hash)){
        get_random_bytes(packet+1+1+LIBEFPIX_PACKAGE_SIZE, LIBEFPIX_POW_NONCE_SIZE);
        crypto_blake2b(pow_hash, LIBEFPIX_HASH_SIZE, packet+1+1, LIBEFPIX_PACKAGE_SIZE+LIBEFPIX_POW_NONCE_SIZE);
    }
}
bool LIBEFPIX_decode(uint8_t packet[LIBEFPIX_PACKET_SIZE], LIBEFPIX_Identity identity, LIBEFPIX_Recv* recv,
    bool (*hash_check_and_relay)(uint8_t[LIBEFPIX_HASH_SIZE], uint8_t[LIBEFPIX_PACKET_SIZE]),
    bool (*get_contact_from_alias)(uint8_t[LIBEFPIX_ALIAS_SIZE], LIBEFPIX_Contact*),
    void (*get_timestamp)(uint8_t[LIBEFPIX_TIMESTAMP_SIZE]),
    uint32_t (*get_age)(uint8_t[LIBEFPIX_TIMESTAMP_SIZE], uint8_t[LIBEFPIX_TIMESTAMP_SIZE])
    ){

    uint8_t hash[LIBEFPIX_HASH_SIZE], pow_hash[LIBEFPIX_HASH_SIZE];
    uint8_t version, type;
    uint8_t mac[16], nonce[24], ephemeral_pk[32], shared_secret[32], cipher[LIBEFPIX_ENCRYPT_SIZE], from_decrypt[LIBEFPIX_ENCRYPT_SIZE];
    uint8_t their_alias[LIBEFPIX_ALIAS_SIZE];
    static uint8_t anon_alias[LIBEFPIX_ALIAS_SIZE]={0};
    uint8_t signature[64];

    crypto_blake2b(hash, LIBEFPIX_HASH_SIZE, packet+1+1, LIBEFPIX_PACKAGE_SIZE);
    crypto_blake2b(pow_hash, LIBEFPIX_HASH_SIZE, packet+1+1, LIBEFPIX_PACKAGE_SIZE+LIBEFPIX_POW_NONCE_SIZE);
    if (!verify_pow(pow_hash)) return false;
    if (!hash_check_and_relay(hash, packet)) return false;
    get_timestamp(recv->recv_timestamp);
    memcpy(&version, packet, 1);
    memcpy(&type, packet+1, 1);
    if (type==LIBEFPIX_UNICAST){
        memcpy(mac, packet+1+1, 16);
        memcpy(nonce, packet+1+1+16, 24);
        memcpy(ephemeral_pk, packet+1+1+16+24, 32);
        memcpy(cipher, packet+1+1+16+24+32, LIBEFPIX_ENCRYPT_SIZE);
        crypto_x25519(shared_secret, identity.kx_secret_key, ephemeral_pk);
        if (crypto_aead_unlock(from_decrypt, mac, shared_secret, nonce, NULL, 0, cipher, LIBEFPIX_ENCRYPT_SIZE)!=0) return false;
        memcpy(their_alias, from_decrypt, LIBEFPIX_ALIAS_SIZE);
        memcpy(recv->send_timestamp, from_decrypt+LIBEFPIX_ALIAS_SIZE, LIBEFPIX_TIMESTAMP_SIZE);
        if (get_age(recv->recv_timestamp, recv->send_timestamp)>LIBEFPIX_MAX_AGE) return false;
        memcpy(recv->internal_address, from_decrypt+LIBEFPIX_ALIAS_SIZE+LIBEFPIX_TIMESTAMP_SIZE, LIBEFPIX_INTERNAL_ADDRESS_SIZE);
        memcpy(recv->message, from_decrypt+LIBEFPIX_ALIAS_SIZE+LIBEFPIX_TIMESTAMP_SIZE+LIBEFPIX_INTERNAL_ADDRESS_SIZE, LIBEFPIX_MESSAGE_SIZE);
        if (memcmp(their_alias, anon_alias, LIBEFPIX_ALIAS_SIZE)==0 || !get_contact_from_alias(their_alias, &(recv->contact))) {
            recv->unknown=true;
            return true;
        }
        memcpy(signature, from_decrypt+LIBEFPIX_ALIAS_SIZE+LIBEFPIX_TIMESTAMP_SIZE+LIBEFPIX_INTERNAL_ADDRESS_SIZE+LIBEFPIX_MESSAGE_SIZE, 64);
        if (!crypto_eddsa_check(signature, recv->contact.sign_public_key, from_decrypt, LIBEFPIX_PAYLOAD_SIZE)) return false;
        recv->unknown=false;
        return true;
    }
    else{
        recv->broadcast=true;
        memcpy(recv->send_timestamp, packet+1+1+32, LIBEFPIX_TIMESTAMP_SIZE);
        memcpy(recv->internal_address, packet+1+1+32+LIBEFPIX_TIMESTAMP_SIZE, LIBEFPIX_INTERNAL_ADDRESS_SIZE);
        memcpy(recv->broadcast_message, packet+1+1+32+LIBEFPIX_TIMESTAMP_SIZE+LIBEFPIX_INTERNAL_ADDRESS_SIZE, LIBEFPIX_BROADCAST_MESSAGE_SIZE);
        if(type==LIBEFPIX_SIGNED_BROADCAST){
            memcpy(recv->contact.sign_public_key, packet+1+1, 32);
            memcpy(signature, packet+1+1+32+LIBEFPIX_TIMESTAMP_SIZE+LIBEFPIX_INTERNAL_ADDRESS_SIZE+LIBEFPIX_BROADCAST_MESSAGE_SIZE, 64);
            if (!crypto_eddsa_check(signature, recv->contact.sign_public_key, packet+1+1+32, LIBEFPIX_BROADCAST_MESSAGE_SIZE+LIBEFPIX_TIMESTAMP_SIZE+LIBEFPIX_INTERNAL_ADDRESS_SIZE)) return false;
            recv->unknown=false;
        }
        else{recv->unknown=true;}
        return true;
    }
}