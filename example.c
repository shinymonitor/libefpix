//=============================================================
// EXAMPLE CODE
//=============================================================
#define LIBEFPIX_IMPLEMENTATION
#include "libefpix.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

//=============================================================
static bool relay(uint8_t packet[LIBEFPIX_PACKET_SIZE]) {
    printf("RELAY: ");
    for (size_t i = 0; i < LIBEFPIX_PACKET_SIZE; i++) printf("%02x", packet[i]);
    printf("\n");
    return true;
}

//=============================================================
int main(void) {
    if (!LIBEFPIX_init()) {
        printf("FAILED TO INIT LIBSODIUM\n");
        return 1;
    }

    LIBEFPIX_Identity alice, bob;
    LIBEFPIX_generate_identity(&alice);
    LIBEFPIX_generate_identity(&bob);

    uint8_t alice_alias[LIBEFPIX_CFG_ALIAS_SIZE] = {0};
    uint8_t bob_alias[LIBEFPIX_CFG_ALIAS_SIZE] = {0};
    strncpy((char*)alice_alias, "Alice", LIBEFPIX_CFG_ALIAS_SIZE - 1);
    strncpy((char*)bob_alias, "Bob", LIBEFPIX_CFG_ALIAS_SIZE - 1);

    LIBEFPIX_add_contact(bob_alias, alice_alias, bob.encrypt_pk, bob.sign_pk);
    LIBEFPIX_add_contact(alice_alias, bob_alias, alice.encrypt_pk, alice.sign_pk);

    LIBEFPIX_Send send_msg = {0};
    send_msg.packet_type = LIBEFPIX_PT_SUC;
    memcpy(send_msg.recv_alias, bob_alias, LIBEFPIX_CFG_ALIAS_SIZE);
    strncpy((char*)send_msg.message, "Hello Bob, this is Alice!", LIBEFPIX_CFG_MESSAGE_SIZE - 1);

    uint8_t packet[LIBEFPIX_PACKET_SIZE];
    if (!LIBEFPIX_create_packet(&send_msg, &alice, packet, relay)) {
        printf("FAILED TO CREATE PACKET\n");
        return 1;
    }

    LIBEFPIX__hash_store_count = 0;

    LIBEFPIX_Recv recv_msg = {0};
    bool decode_result = LIBEFPIX_handle_packet(packet, &bob, &recv_msg, relay);

    bool pass = decode_result
        && recv_msg.packet_type == LIBEFPIX_PT_SUC
        && memcmp(recv_msg.send_alias, alice_alias, LIBEFPIX_CFG_ALIAS_SIZE) == 0
        && memcmp(recv_msg.message, send_msg.message, LIBEFPIX_CFG_MESSAGE_SIZE) == 0;

    printf("%s\n", pass ? "RECEIVED BY BOB" : "FAIL");
    printf("MESSAGE: %s\n", recv_msg.message);
    return 0;
}
