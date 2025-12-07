//=============================================================
//TEST CODE
//=============================================================
#include "libefpix_config.h"
#include "libefpix.h"
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
//=============================PASSED FUNCTIONS================================
static uint8_t stored_hashes[100][LIBEFPIX_HASH_SIZE];
static int hash_count = 0;
static LIBEFPIX_Contact contacts[10];
static int contact_count = 0;
void print_hex(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
bool hash_check_and_relay(uint8_t hash[LIBEFPIX_HASH_SIZE], uint8_t packet[LIBEFPIX_PACKET_SIZE]) {
    for (int i = 0; i < hash_count; i++) {
        if (memcmp(stored_hashes[i], hash, LIBEFPIX_HASH_SIZE) == 0) return false;
    }
    if (hash_count < 100) {
        memcpy(stored_hashes[hash_count], hash, LIBEFPIX_HASH_SIZE);
        hash_count++;
    }
    printf("RELAY: ");
    print_hex(packet, LIBEFPIX_PACKET_SIZE);
    return true;
}
bool get_contact_from_alias(uint8_t alias[LIBEFPIX_ALIAS_SIZE], LIBEFPIX_Contact* contact) {
    for (int i = 0; i < contact_count; i++) {
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
    if (recv_ts >= send_ts) {
        return (uint32_t)(recv_ts - send_ts);
    } else {
        return UINT32_MAX;
    }
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
//==============================TESTS===============================
bool test_unicast_signed(LIBEFPIX_Identity* alice, LIBEFPIX_Identity* bob) {
    printf("\n=== Test 1: Unicast Signed Message ===\n");
    LIBEFPIX_Send send_msg = {0};
    send_msg.anonymous = false;
    send_msg.broadcast = false;
    send_msg.identity = *alice;
    safe_alias_copy(send_msg.my_alias, "Alice");
    memcpy(send_msg.receiver_kx_public_key, bob->kx_public_key, 32);
    get_timestamp(send_msg.timestamp);
    memcpy(send_msg.internal_address, "001", 3);
    strncpy((char*)send_msg.message, "Hello Bob, this is Alice!", LIBEFPIX_MESSAGE_SIZE - 1);
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(send_msg, packet);
    LIBEFPIX_Recv recv_msg = {0};
    bool decode_result = LIBEFPIX_decode(packet, *bob, &recv_msg, 
                                hash_check_and_relay, 
                                get_contact_from_alias, 
                                get_timestamp, 
                                get_age);
    bool pass = (decode_result && !recv_msg.unknown && !recv_msg.broadcast &&
                memcmp(recv_msg.contact.their_alias, send_msg.my_alias, LIBEFPIX_ALIAS_SIZE)==0 && 
                memcmp(recv_msg.message, send_msg.message, LIBEFPIX_MESSAGE_SIZE)==0);
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}
bool test_unicast_anonymous(LIBEFPIX_Identity* bob) {
    printf("\n=== Test 2: Unicast Anonymous Message ===\n");
    LIBEFPIX_Send anon_msg = {0};
    anon_msg.anonymous = true;
    anon_msg.broadcast = false;
    memcpy(anon_msg.receiver_kx_public_key, bob->kx_public_key, 32);
    get_timestamp(anon_msg.timestamp);
    memcpy(anon_msg.internal_address, "002", 3);
    strncpy((char*)anon_msg.message, "Anonymous message", LIBEFPIX_MESSAGE_SIZE - 1);
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(anon_msg, packet);
    LIBEFPIX_Recv recv_msg = {0};
    bool decode_result = LIBEFPIX_decode(packet, *bob, &recv_msg,
                                hash_check_and_relay,
                                get_contact_from_alias,
                                get_timestamp,
                                get_age);
    bool pass = (decode_result && recv_msg.unknown && !recv_msg.broadcast &&
                memcmp(recv_msg.message, anon_msg.message, LIBEFPIX_MESSAGE_SIZE)==0);
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}
bool test_broadcast_signed(LIBEFPIX_Identity* alice, LIBEFPIX_Identity* bob) {
    printf("\n=== Test 3: Signed Broadcast Message ===\n");
    LIBEFPIX_Send broadcast_msg = {0};
    broadcast_msg.anonymous = false;
    broadcast_msg.broadcast = true;
    broadcast_msg.identity = *alice;
    get_timestamp(broadcast_msg.timestamp);
    memcpy(broadcast_msg.internal_address, "003", 3);
    strncpy((char*)broadcast_msg.broadcast_message, "Hello everyone!", LIBEFPIX_BROADCAST_MESSAGE_SIZE - 1);
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(broadcast_msg, packet);
    LIBEFPIX_Recv recv_msg = {0};
    bool decode_result = LIBEFPIX_decode(packet, *bob, &recv_msg,
                                hash_check_and_relay,
                                get_contact_from_alias,
                                get_timestamp,
                                get_age);
    bool pass = (decode_result && !recv_msg.unknown && recv_msg.broadcast &&
                memcmp(recv_msg.broadcast_message, broadcast_msg.broadcast_message, LIBEFPIX_BROADCAST_MESSAGE_SIZE)==0 &&
                memcmp(recv_msg.contact.sign_public_key, alice->sign_public_key, 32)==0);
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}
bool test_broadcast_anonymous(LIBEFPIX_Identity* bob) {
    printf("\n=== Test 4: Anonymous Broadcast Message ===\n");
    LIBEFPIX_Send anon_broadcast = {0};
    anon_broadcast.anonymous = true;
    anon_broadcast.broadcast = true;
    get_timestamp(anon_broadcast.timestamp);
    memcpy(anon_broadcast.internal_address, "004", 3);
    strncpy((char*)anon_broadcast.broadcast_message, "Anonymous broadcast", LIBEFPIX_BROADCAST_MESSAGE_SIZE - 1);
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(anon_broadcast, packet);
    LIBEFPIX_Recv recv_msg = {0};
    bool decode_result = LIBEFPIX_decode(packet, *bob, &recv_msg,
                                hash_check_and_relay,
                                get_contact_from_alias,
                                get_timestamp,
                                get_age);
    bool pass = (decode_result && recv_msg.unknown && recv_msg.broadcast &&
                memcmp(recv_msg.broadcast_message, anon_broadcast.broadcast_message, LIBEFPIX_BROADCAST_MESSAGE_SIZE)==0);
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}
bool test_tampered_message(LIBEFPIX_Identity* alice, LIBEFPIX_Identity* bob) {
    printf("\n=== Test 5: Tampered Message ===\n");
    LIBEFPIX_Send send_msg = {0};
    send_msg.anonymous = false;
    send_msg.broadcast = false;
    send_msg.identity = *alice;
    safe_alias_copy(send_msg.my_alias, "Alice");
    memcpy(send_msg.receiver_kx_public_key, bob->kx_public_key, 32);
    get_timestamp(send_msg.timestamp);
    memcpy(send_msg.internal_address, "005", 3);
    strncpy((char*)send_msg.message, "Original message", LIBEFPIX_MESSAGE_SIZE - 1);
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(send_msg, packet);
    packet[LIBEFPIX_HASH_SIZE + 100] ^= 0xFF;
    LIBEFPIX_Recv recv_msg = {0};
    bool decode_result = LIBEFPIX_decode(packet, *bob, &recv_msg,
                                hash_check_and_relay,
                                get_contact_from_alias,
                                get_timestamp,
                                get_age);
    bool pass = !decode_result;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}
bool test_duplicate_message(LIBEFPIX_Identity* alice, LIBEFPIX_Identity* bob) {
    printf("\n=== Test 6: Duplicate Message ===\n");
    LIBEFPIX_Send send_msg = {0};
    send_msg.anonymous = false;
    send_msg.broadcast = false;
    send_msg.identity = *alice;
    safe_alias_copy(send_msg.my_alias, "Alice");
    memcpy(send_msg.receiver_kx_public_key, bob->kx_public_key, 32);
    get_timestamp(send_msg.timestamp);
    memcpy(send_msg.internal_address, "006", 3);
    strncpy((char*)send_msg.message, "Test duplicate", LIBEFPIX_MESSAGE_SIZE - 1);
    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    LIBEFPIX_encode(send_msg, packet);
    LIBEFPIX_Recv recv_msg1 = {0};
    bool first_result = LIBEFPIX_decode(packet, *bob, &recv_msg1,
                              hash_check_and_relay,
                              get_contact_from_alias,
                              get_timestamp,
                              get_age);
    LIBEFPIX_Recv recv_msg2 = {0};
    bool second_result = LIBEFPIX_decode(packet, *bob, &recv_msg2,
                               hash_check_and_relay,
                               get_contact_from_alias,
                               get_timestamp,
                               get_age);
    bool pass = first_result && !second_result;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}
//=============================================================
int main() {
    LIBEFPIX_Identity alice, bob;
    LIBEFPIX_generate_identity(&alice);
    LIBEFPIX_generate_identity(&bob);

    add_test_contact("Alice", alice.kx_public_key, alice.sign_public_key, "Bob");
    add_test_contact("Bob", bob.kx_public_key, bob.sign_public_key, "Alice");
    
    int passed = 0, total = 6;
    
    if (test_unicast_signed(&alice, &bob)) passed++;
    if (test_unicast_anonymous(&bob)) passed++;
    if (test_broadcast_signed(&alice, &bob)) passed++;
    if (test_broadcast_anonymous(&bob)) passed++;
    if (test_tampered_message(&alice, &bob)) passed++;
    if (test_duplicate_message(&alice, &bob)) passed++;
    
    printf("\n=== RESULTS ===\n");
    printf("Passed: %d/%d tests\n", passed, total);

    return 0;
}