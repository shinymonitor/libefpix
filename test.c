//=============================================================
// TEST CODE
//=============================================================
#define LIBEFPIX_IMPLEMENTATION
#include "libefpix.h"
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>

//=============================ALLOC================================
#define HASH_STORE_SIZE    100
#define CONTACT_STORE_SIZE 100
static uint8_t stored_hashes[HASH_STORE_SIZE][LIBEFPIX_HASH_SIZE];
static size_t  hash_count = 0;
static LIBEFPIX_Contact contacts[CONTACT_STORE_SIZE];
static size_t  contact_count = 0;

//=============================PASSED FUNCTIONS================================
void print_hex(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

bool hash_check_and_relay(uint8_t hash[LIBEFPIX_HASH_SIZE], uint8_t packet[LIBEFPIX_PACKET_SIZE]) {
    for (size_t i = 0; i < hash_count; i++)
        if (memcmp(stored_hashes[i], hash, LIBEFPIX_HASH_SIZE) == 0) return false;
    if (hash_count < HASH_STORE_SIZE) {
        memcpy(stored_hashes[hash_count++], hash, LIBEFPIX_HASH_SIZE);
    }
    printf("RELAY: ");
    print_hex(packet, LIBEFPIX_PACKET_SIZE);
    return true;
}

bool get_contact_from_alias(uint8_t alias[LIBEFPIX_ALIAS_SIZE], LIBEFPIX_Contact *contact) {
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
    return (recv_ts >= send_ts) ? (uint32_t)(recv_ts - send_ts) : UINT32_MAX;
}

//=============================HELPER FUNCTIONS================================
void add_test_contact(
        const char *their_alias_str,
        uint8_t encrypt_public_key[LIBEFPIX_ENC_PK_SIZE],
        uint8_t sign_public_key[LIBEFPIX_SIGN_PK_SIZE],
        const char *my_alias_str
    ) {
    if (contact_count >= CONTACT_STORE_SIZE) return;
    LIBEFPIX_Contact *c = &contacts[contact_count++];
    memset(c->their_alias, 0, LIBEFPIX_ALIAS_SIZE);
    memset(c->my_alias,    0, LIBEFPIX_ALIAS_SIZE);
    strncpy((char *)c->their_alias, their_alias_str, LIBEFPIX_ALIAS_SIZE - 1);
    strncpy((char *)c->my_alias,    my_alias_str,    LIBEFPIX_ALIAS_SIZE - 1);
    memcpy(c->encrypt_public_key, encrypt_public_key, LIBEFPIX_ENC_PK_SIZE);
    memcpy(c->sign_public_key,    sign_public_key,    LIBEFPIX_SIGN_PK_SIZE);
}

void safe_alias_copy(uint8_t dest[LIBEFPIX_ALIAS_SIZE], const char *src) {
    memset(dest, 0, LIBEFPIX_ALIAS_SIZE);
    strncpy((char *)dest, src, LIBEFPIX_ALIAS_SIZE - 1);
}

//==============================TESTS===============================
bool test_unicast_signed(LIBEFPIX_Identity *alice, LIBEFPIX_Identity *bob) {
    printf("\n=== Test 1: Unicast Signed Message ===\n");
    LIBEFPIX_Send send_msg = {0};
    safe_alias_copy(send_msg.alias, "Alice");
    get_timestamp(send_msg.send_timestamp);
    strncpy((char *)send_msg.message, "Hello Bob, this is Alice!", LIBEFPIX_MESSAGE_SIZE - 1);
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(&send_msg, alice, bob->encrypt_public_key, false, false, packet);
    LIBEFPIX_Recv recv_msg = {0};
    bool ok = LIBEFPIX_decode(packet, bob, &recv_msg, hash_check_and_relay, get_contact_from_alias, get_timestamp, get_age);
    bool pass = ok && !recv_msg.unknown && !recv_msg.broadcast && memcmp(recv_msg.contact.their_alias, send_msg.alias, LIBEFPIX_ALIAS_SIZE) == 0 && memcmp(recv_msg.message, send_msg.message, LIBEFPIX_MESSAGE_SIZE) == 0;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

bool test_unicast_anonymous(LIBEFPIX_Identity *bob) {
    printf("\n=== Test 2: Unicast Anonymous Message ===\n");
    LIBEFPIX_Send send_msg = {0};
    get_timestamp(send_msg.send_timestamp);
    strncpy((char *)send_msg.message, "Anonymous message", LIBEFPIX_MESSAGE_SIZE - 1);
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(&send_msg, NULL, bob->encrypt_public_key, true, false, packet);
    LIBEFPIX_Recv recv_msg = {0};
    bool ok = LIBEFPIX_decode(packet, bob, &recv_msg, hash_check_and_relay, get_contact_from_alias, get_timestamp, get_age);
    bool pass = ok && recv_msg.unknown && !recv_msg.broadcast && memcmp(recv_msg.message, send_msg.message, LIBEFPIX_MESSAGE_SIZE) == 0;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

bool test_broadcast_signed(LIBEFPIX_Identity *alice, LIBEFPIX_Identity *bob) {
    printf("\n=== Test 3: Signed Broadcast Message ===\n");
    LIBEFPIX_Send send_msg = {0};
    get_timestamp(send_msg.send_timestamp);
    strncpy((char *)send_msg.message, "Hello everyone!", LIBEFPIX_MESSAGE_SIZE - 1);
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(&send_msg, alice, NULL, false, true, packet);
    LIBEFPIX_Recv recv_msg = {0};
    bool ok = LIBEFPIX_decode(packet, bob, &recv_msg, hash_check_and_relay, get_contact_from_alias, get_timestamp, get_age);
    bool pass = ok && !recv_msg.unknown && recv_msg.broadcast && memcmp(recv_msg.message, send_msg.message, LIBEFPIX_MESSAGE_SIZE) == 0 && memcmp(recv_msg.contact.sign_public_key, alice->sign_public_key, LIBEFPIX_SIGN_PK_SIZE) == 0;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

bool test_broadcast_anonymous(LIBEFPIX_Identity *bob) {
    printf("\n=== Test 4: Anonymous Broadcast Message ===\n");
    LIBEFPIX_Send send_msg = {0};
    get_timestamp(send_msg.send_timestamp);
    strncpy((char *)send_msg.message, "Anonymous broadcast", LIBEFPIX_MESSAGE_SIZE - 1);
    LIBEFPIX_Identity dummy = {0};
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(&send_msg, &dummy, NULL, true, true, packet);
    LIBEFPIX_Recv recv_msg = {0};
    bool ok = LIBEFPIX_decode(packet, bob, &recv_msg, hash_check_and_relay, get_contact_from_alias, get_timestamp, get_age);
    bool pass = ok && recv_msg.unknown && recv_msg.broadcast && memcmp(recv_msg.message, send_msg.message, LIBEFPIX_MESSAGE_SIZE) == 0;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

bool test_tampered_message(LIBEFPIX_Identity *alice, LIBEFPIX_Identity *bob) {
    printf("\n=== Test 5: Tampered Message ===\n");
    LIBEFPIX_Send send_msg = {0};
    safe_alias_copy(send_msg.alias, "Alice");
    get_timestamp(send_msg.send_timestamp);
    strncpy((char *)send_msg.message, "Original message", LIBEFPIX_MESSAGE_SIZE - 1);
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(&send_msg, alice, bob->encrypt_public_key, false, false, packet);
    packet[2 + 50] ^= 0xFF;
    LIBEFPIX_Recv recv_msg = {0};
    bool ok = LIBEFPIX_decode(packet, bob, &recv_msg, hash_check_and_relay, get_contact_from_alias, get_timestamp, get_age);
    bool pass = !ok;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

bool test_duplicate_message(LIBEFPIX_Identity *alice, LIBEFPIX_Identity *bob) {
    printf("\n=== Test 6: Duplicate Message ===\n");
    LIBEFPIX_Send send_msg = {0};
    safe_alias_copy(send_msg.alias, "Alice");
    get_timestamp(send_msg.send_timestamp);
    strncpy((char *)send_msg.message, "Test duplicate", LIBEFPIX_MESSAGE_SIZE - 1);
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(&send_msg, alice, bob->encrypt_public_key, false, false, packet);
    LIBEFPIX_Recv recv1 = {0}, recv2 = {0};
    bool first  = LIBEFPIX_decode(packet, bob, &recv1, hash_check_and_relay, get_contact_from_alias, get_timestamp, get_age);
    bool second = LIBEFPIX_decode(packet, bob, &recv2, hash_check_and_relay, get_contact_from_alias, get_timestamp, get_age);
    bool pass = first && !second;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

//=============================================================
int main() {
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }
    LIBEFPIX_Identity alice, bob;
    LIBEFPIX_generate_identity(&alice);
    LIBEFPIX_generate_identity(&bob);
    add_test_contact("Alice", alice.encrypt_public_key, alice.sign_public_key, "Bob");
    add_test_contact("Bob",   bob.encrypt_public_key,   bob.sign_public_key,   "Alice");
    int passed = 0, total = 6;
    if (test_unicast_signed    (&alice, &bob)) passed++;
    if (test_unicast_anonymous (&bob))         passed++;
    if (test_broadcast_signed  (&alice, &bob)) passed++;
    if (test_broadcast_anonymous(&bob))        passed++;
    if (test_tampered_message  (&alice, &bob)) passed++;
    if (test_duplicate_message (&alice, &bob)) passed++;
    printf("\n=== RESULTS ===\n");
    printf("Passed: %d/%d tests\n", passed, total);
    return (passed == total) ? 0 : 1;
}