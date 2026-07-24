//=============================================================
// TEST CODE
//=============================================================
#define LIBEFPIX_IMPLEMENTATION
#include "libefpix.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

//=============================RELAY================================
static bool relay(uint8_t packet[LIBEFPIX_PACKET_SIZE]) {
    printf("RELAY: ");
    for (size_t i = 0; i < LIBEFPIX_PACKET_SIZE; i++) printf("%02x", packet[i]);
    printf("\n");
    return true;
}

//=============================HELPERS================================
static void set_alias(uint8_t dest[LIBEFPIX_CFG_ALIAS_SIZE], const char *src) {
    memset(dest, 0, LIBEFPIX_CFG_ALIAS_SIZE);
    strncpy((char *)dest, src, LIBEFPIX_CFG_ALIAS_SIZE - 1);
}

static void reset_hash_store(void) {
    LIBEFPIX__hash_store_count = 0;
}

static void remine_pow(uint8_t packet[LIBEFPIX_PACKET_SIZE], uint8_t pow_zeros) {
    uint8_t pow_hash[LIBEFPIX_VL_HASH_SIZE];
    do {
        randombytes_buf(packet + LIBEFPIX_UC_POW_NONCE_OFF, LIBEFPIX_CFG_POW_NONCE_SIZE);
        crypto_generichash(pow_hash, LIBEFPIX_VL_HASH_SIZE, packet + LIBEFPIX_PT_HEADER_SIZE, LIBEFPIX_PACKET_SIZE - LIBEFPIX_PT_HEADER_SIZE, NULL, 0);
    } while (!LIBEFPIX__verify_pow(pow_hash, pow_zeros));
}

//==============================TESTS===============================
static bool test_unicast_signed(LIBEFPIX_Identity *alice, LIBEFPIX_Identity *bob,
                                 uint8_t alice_alias[LIBEFPIX_CFG_ALIAS_SIZE],
                                 uint8_t bob_alias[LIBEFPIX_CFG_ALIAS_SIZE]) {
    printf("\n=== Test 1: Unicast Signed Message (SUC) ===\n");
    LIBEFPIX_Send send_msg = {0};
    send_msg.packet_type = LIBEFPIX_PT_SUC;
    memcpy(send_msg.recv_alias, bob_alias, LIBEFPIX_CFG_ALIAS_SIZE);
    strncpy((char *)send_msg.message, "Hello Bob, this is Alice!", LIBEFPIX_CFG_MESSAGE_SIZE - 1);

    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    if (!LIBEFPIX_create_packet(&send_msg, alice, packet, relay)) { printf("Result: FAIL (create)\n"); return false; }

    reset_hash_store();
    LIBEFPIX_Recv recv_msg = {0};
    bool ok = LIBEFPIX_handle_packet(packet, bob, &recv_msg, relay);
    bool pass = ok
        && recv_msg.packet_type == LIBEFPIX_PT_SUC
        && memcmp(recv_msg.send_alias, alice_alias, LIBEFPIX_CFG_ALIAS_SIZE) == 0
        && memcmp(recv_msg.recv_alias, bob_alias, LIBEFPIX_CFG_ALIAS_SIZE) == 0
        && memcmp(recv_msg.message, send_msg.message, LIBEFPIX_CFG_MESSAGE_SIZE) == 0;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

static bool test_unicast_anonymous(LIBEFPIX_Identity *alice, LIBEFPIX_Identity *bob,
                                    uint8_t bob_alias[LIBEFPIX_CFG_ALIAS_SIZE]) {
    printf("\n=== Test 2: Unicast Anonymous Message (AUC) ===\n");
    uint8_t zero_alias[LIBEFPIX_CFG_ALIAS_SIZE] = {0};
    LIBEFPIX_Send send_msg = {0};
    send_msg.packet_type = LIBEFPIX_PT_AUC;
    memcpy(send_msg.recv_alias, bob_alias, LIBEFPIX_CFG_ALIAS_SIZE);
    strncpy((char *)send_msg.message, "Anonymous message", LIBEFPIX_CFG_MESSAGE_SIZE - 1);

    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    if (!LIBEFPIX_create_packet(&send_msg, alice, packet, relay)) { printf("Result: FAIL (create)\n"); return false; }

    reset_hash_store();
    LIBEFPIX_Recv recv_msg = {0};
    bool ok = LIBEFPIX_handle_packet(packet, bob, &recv_msg, relay);
    bool pass = ok
        && recv_msg.packet_type == LIBEFPIX_PT_AUC
        && memcmp(recv_msg.send_alias, zero_alias, LIBEFPIX_CFG_ALIAS_SIZE) == 0
        && memcmp(recv_msg.recv_alias, zero_alias, LIBEFPIX_CFG_ALIAS_SIZE) == 0
        && memcmp(recv_msg.message, send_msg.message, LIBEFPIX_CFG_MESSAGE_SIZE) == 0;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

static bool test_broadcast_signed(LIBEFPIX_Identity *alice, LIBEFPIX_Identity *bob,
                                   uint8_t alice_alias[LIBEFPIX_CFG_ALIAS_SIZE],
                                   uint8_t bob_alias[LIBEFPIX_CFG_ALIAS_SIZE]) {
    printf("\n=== Test 3: Broadcast Signed Message (SBC) ===\n");
    uint8_t zero_alias[LIBEFPIX_CFG_ALIAS_SIZE] = {0};
    LIBEFPIX_Send send_msg = {0};
    send_msg.packet_type = LIBEFPIX_PT_SBC;
    memcpy(send_msg.recv_alias, bob_alias, LIBEFPIX_CFG_ALIAS_SIZE);
    strncpy((char *)send_msg.message, "Hello everyone!", LIBEFPIX_CFG_MESSAGE_SIZE - 1);

    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    if (!LIBEFPIX_create_packet(&send_msg, alice, packet, relay)) { printf("Result: FAIL (create)\n"); return false; }

    reset_hash_store();
    LIBEFPIX_Recv recv_msg = {0};
    bool ok = LIBEFPIX_handle_packet(packet, bob, &recv_msg, relay);
    bool pass = ok
        && recv_msg.packet_type == LIBEFPIX_PT_SBC
        && memcmp(recv_msg.send_alias, alice_alias, LIBEFPIX_CFG_ALIAS_SIZE) == 0
        && memcmp(recv_msg.recv_alias, zero_alias, LIBEFPIX_CFG_ALIAS_SIZE) == 0
        && memcmp(recv_msg.message, send_msg.message, LIBEFPIX_CFG_MESSAGE_SIZE) == 0;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

static bool test_broadcast_anonymous(LIBEFPIX_Identity *alice, LIBEFPIX_Identity *bob,
                                      uint8_t bob_alias[LIBEFPIX_CFG_ALIAS_SIZE]) {
    printf("\n=== Test 4: Broadcast Anonymous Message (ABC) ===\n");
    uint8_t zero_alias[LIBEFPIX_CFG_ALIAS_SIZE] = {0};
    LIBEFPIX_Send send_msg = {0};
    send_msg.packet_type = LIBEFPIX_PT_ABC;
    memcpy(send_msg.recv_alias, bob_alias, LIBEFPIX_CFG_ALIAS_SIZE);
    strncpy((char *)send_msg.message, "Anonymous broadcast", LIBEFPIX_CFG_MESSAGE_SIZE - 1);

    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    if (!LIBEFPIX_create_packet(&send_msg, alice, packet, relay)) { printf("Result: FAIL (create)\n"); return false; }

    reset_hash_store();
    LIBEFPIX_Recv recv_msg = {0};
    bool ok = LIBEFPIX_handle_packet(packet, bob, &recv_msg, relay);
    bool pass = ok
        && recv_msg.packet_type == LIBEFPIX_PT_ABC
        && memcmp(recv_msg.send_alias, zero_alias, LIBEFPIX_CFG_ALIAS_SIZE) == 0
        && memcmp(recv_msg.recv_alias, zero_alias, LIBEFPIX_CFG_ALIAS_SIZE) == 0
        && memcmp(recv_msg.message, send_msg.message, LIBEFPIX_CFG_MESSAGE_SIZE) == 0;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

static bool test_tampered_message(LIBEFPIX_Identity *alice, LIBEFPIX_Identity *bob,
                                   uint8_t bob_alias[LIBEFPIX_CFG_ALIAS_SIZE]) {
    printf("\n=== Test 5: Tampered Message ===\n");
    LIBEFPIX_Send send_msg = {0};
    send_msg.packet_type = LIBEFPIX_PT_SUC;
    memcpy(send_msg.recv_alias, bob_alias, LIBEFPIX_CFG_ALIAS_SIZE);
    strncpy((char *)send_msg.message, "Original message", LIBEFPIX_CFG_MESSAGE_SIZE - 1);

    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    if (!LIBEFPIX_create_packet(&send_msg, alice, packet, relay)) { printf("Result: FAIL (create)\n"); return false; }

    packet[LIBEFPIX_UC_SEALED_OFF + 20] ^= 0xFF;
    remine_pow(packet, LIBEFPIX_CFG_UC_POW_ZEROS);

    reset_hash_store();
    LIBEFPIX_Recv recv_msg = {0};
    bool ok = LIBEFPIX_handle_packet(packet, bob, &recv_msg, relay);
    bool pass = !ok;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

static bool test_duplicate_message(LIBEFPIX_Identity *alice, LIBEFPIX_Identity *bob,
                                    uint8_t bob_alias[LIBEFPIX_CFG_ALIAS_SIZE]) {
    printf("\n=== Test 6: Duplicate Message ===\n");
    LIBEFPIX_Send send_msg = {0};
    send_msg.packet_type = LIBEFPIX_PT_SUC;
    memcpy(send_msg.recv_alias, bob_alias, LIBEFPIX_CFG_ALIAS_SIZE);
    strncpy((char *)send_msg.message, "Test duplicate", LIBEFPIX_CFG_MESSAGE_SIZE - 1);

    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    if (!LIBEFPIX_create_packet(&send_msg, alice, packet, relay)) { printf("Result: FAIL (create)\n"); return false; }

    reset_hash_store();
    LIBEFPIX_Recv recv1 = {0}, recv2 = {0};
    bool first  = LIBEFPIX_handle_packet(packet, bob, &recv1, relay);
    bool second = LIBEFPIX_handle_packet(packet, bob, &recv2, relay);
    bool pass = first && !second;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

//=============================================================
int main(void) {
    if (!LIBEFPIX_init()) { fprintf(stderr, "sodium init failed\n"); return 1; }

    LIBEFPIX_Identity alice, bob;
    LIBEFPIX_generate_identity(&alice);
    LIBEFPIX_generate_identity(&bob);

    uint8_t alice_alias[LIBEFPIX_CFG_ALIAS_SIZE], bob_alias[LIBEFPIX_CFG_ALIAS_SIZE];
    set_alias(alice_alias, "Alice");
    set_alias(bob_alias, "Bob");

    LIBEFPIX_add_contact(bob_alias, alice_alias, bob.encrypt_pk, bob.sign_pk);
    LIBEFPIX_add_contact(alice_alias, bob_alias, alice.encrypt_pk, alice.sign_pk);

    int passed = 0, total = 6;
    if (test_unicast_signed(&alice, &bob, alice_alias, bob_alias))      passed++;
    if (test_unicast_anonymous(&alice, &bob, bob_alias))                passed++;
    if (test_broadcast_signed(&alice, &bob, alice_alias, bob_alias))    passed++;
    if (test_broadcast_anonymous(&alice, &bob, bob_alias))              passed++;
    if (test_tampered_message(&alice, &bob, bob_alias))                 passed++;
    if (test_duplicate_message(&alice, &bob, bob_alias))                passed++;

    printf("\n=== RESULTS ===\n");
    printf("Passed: %d/%d tests\n", passed, total);
    return (passed == total) ? 0 : 1;
}
