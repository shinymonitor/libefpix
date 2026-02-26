//=============================================================
//EXAMPLE CODE
//=============================================================
#include "libefpix_config.h"
#include "libefpix.h"
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
//=============================ALLOC================================
#define HASH_STORE_SIZE 100
#define CONTACT_STORE_SIZE 100
static uint8_t stored_hashes[HASH_STORE_SIZE][LIBEFPIX_HASH_SIZE];
static size_t hash_count = 0;
static LIBEFPIX_Contact contacts[CONTACT_STORE_SIZE];
static size_t contact_count = 0;
//=============================PASSED FUNCTIONS================================
void print_hex(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}
bool hash_check_and_relay(uint8_t hash[LIBEFPIX_HASH_SIZE], uint8_t packet[LIBEFPIX_PACKET_SIZE]) {
    for (size_t i = 0; i < hash_count; i++) if (memcmp(stored_hashes[i], hash, LIBEFPIX_HASH_SIZE) == 0) return false;
    if (hash_count < HASH_STORE_SIZE) {memcpy(stored_hashes[hash_count], hash, LIBEFPIX_HASH_SIZE); hash_count++;}
    printf("RELAY: ");
    print_hex(packet, LIBEFPIX_PACKET_SIZE);
    return true;
}
bool get_contact_from_alias(uint8_t alias[LIBEFPIX_ALIAS_SIZE], LIBEFPIX_Contact* contact) {
    for (size_t i = 0; i < contact_count; i++) {
        if (memcmp(contacts[i].their_alias, alias, LIBEFPIX_ALIAS_SIZE) == 0) {
            memcpy(contact, &contacts[i], sizeof(LIBEFPIX_Contact));
            return true;
        }
    }
    return false;
}
void get_timestamp(uint8_t timestamp[LIBEFPIX_TIMESTAMP_SIZE]) {
    uint64_t now = (uint64_t)time(NULL);
    memcpy(timestamp, &now, LIBEFPIX_TIMESTAMP_SIZE);
}
uint32_t get_age(uint8_t recv_time[LIBEFPIX_TIMESTAMP_SIZE], uint8_t send_time[LIBEFPIX_TIMESTAMP_SIZE]) {
    uint64_t recv_ts, send_ts;
    memcpy(&recv_ts, recv_time, LIBEFPIX_TIMESTAMP_SIZE);
    memcpy(&send_ts, send_time, LIBEFPIX_TIMESTAMP_SIZE);
    if (recv_ts >= send_ts) return (uint32_t)(recv_ts - send_ts);
    else return UINT32_MAX;
}
//=============================HELPER FUNCTIONS================================
void add_test_contact(const char* their_alias_str, uint8_t kx_public_key[32], uint8_t sign_public_key[32], const char* my_alias_str) {
    if (contact_count < 10) {
        memset(contacts[contact_count].their_alias, 0, LIBEFPIX_ALIAS_SIZE);
        memset(contacts[contact_count].my_alias, 0, LIBEFPIX_ALIAS_SIZE);
        strncpy((char*)contacts[contact_count].their_alias, their_alias_str, LIBEFPIX_ALIAS_SIZE - 1);
        strncpy((char*)contacts[contact_count].my_alias, my_alias_str, LIBEFPIX_ALIAS_SIZE - 1);
        memcpy(contacts[contact_count].kx_public_key, kx_public_key, 32);
        memcpy(contacts[contact_count].sign_public_key, sign_public_key, 32);
        ++contact_count;
    }
}
void safe_alias_copy(uint8_t dest[LIBEFPIX_ALIAS_SIZE], const char* src) {
    memset(dest, 0, LIBEFPIX_ALIAS_SIZE);
    strncpy((char*)dest, src, LIBEFPIX_ALIAS_SIZE - 1);
}
//=============================================================
int main() {
    LIBEFPIX_Identity alice, bob;
    LIBEFPIX_generate_identity(&alice);
    LIBEFPIX_generate_identity(&bob);
    add_test_contact("Alice", alice.kx_public_key, alice.sign_public_key, "Bob");
    add_test_contact("Bob", bob.kx_public_key, bob.sign_public_key, "Alice");
    LIBEFPIX_Send send_msg = {0};
    send_msg.anonymous = false;
    send_msg.broadcast = false;
    send_msg.identity = alice;
    safe_alias_copy(send_msg.my_alias, "Alice");
    memcpy(send_msg.receiver_kx_public_key, bob.kx_public_key, 32);
    get_timestamp(send_msg.timestamp);
    memcpy(send_msg.internal_address, "001", 3);
    strncpy((char*)send_msg.message, "Hello Bob, this is Alice!", LIBEFPIX_MESSAGE_SIZE - 1);
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(send_msg, packet);
    LIBEFPIX_Recv recv_msg = {0};
    bool decode_result = LIBEFPIX_decode(packet, bob, &recv_msg, hash_check_and_relay, get_contact_from_alias, get_timestamp, get_age);
    bool pass = (decode_result && !recv_msg.unknown && !recv_msg.broadcast && memcmp(recv_msg.contact.their_alias, send_msg.my_alias, LIBEFPIX_ALIAS_SIZE)==0 && memcmp(recv_msg.message, send_msg.message, LIBEFPIX_MESSAGE_SIZE)==0);
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return 0;
}