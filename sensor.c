#include "contiki.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "aes.h"
#include "ccm_mode.h"
#include "sha256.h"
#include "hmac.h" 
#include "random.h"
#include "uiplib.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/simple-udp.h"
#include "dev/flash.h"
#include "net/netstack.h"
#include "os/net/nullnet/nullnet.h"
#include "net/routing/routing.h"
//#define FLASH_ADDRESS 0x1000
/*---------------------------------------------------------------------------*/
#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define CCM_AUTH_SIZE 8
#define CCM_NONCE_SIZE 13

uip_ipaddr_t dest_ipaddr;

static struct simple_udp_connection broadcast_conn;
static struct simple_udp_connection unicast_conn;

static struct ctimer broadcast_timer;
static struct ctimer listening_timer;

static uip_ipaddr_t broadcast;

uint8_t ciphertext[16+8]; 
uint8_t enc_key[16];

TCCcmMode_t ccm;
uint8_t nonce[CCM_NONCE_SIZE];
uint64_t iv;

uip_ipaddr_t smart_meter_address;

const uint8_t salt[] = {0x00}; 
const uint8_t ikm[32] = {0x3d, 0x9e, 0x76, 0x0f, 0xf5, 0xe9, 0xea, 0xf4, 0x19, 0x8d, 
                          0x0c, 0x02, 0xf1, 0x43, 0xf9, 0x57, 0x90, 0x4a, 0xca, 0x29, 0x73,
                          0x81, 0x2a, 0x93, 0xc1, 0x03, 0x5d, 0x46, 0x86, 0xd0, 0xa3, 0x32};
int packet_number = 1;

bool can_send = false;

typedef struct {
    int sequence_number;
    uint8_t payload[24];
    uint64_t partial_nonce; // 64-bit of the sender address + 5-byte of randomly generated
    unsigned long timestamp;
} udp_packet_t;

typedef struct {
    uint8_t prk[32];
    uint8_t secret_key[32];
    uint8_t current_key[16];
    uip_ipaddr_t link_local_address;
} device_t;
device_t device;
/*---------------------------------------------------------------------------*/
void initialize_AES(const uint8_t *key){
    int result;

    result = tc_aes128_set_encrypt_key(ccm->sched, key);
    if (result != 1) {
        printf("Key set failed with error %d\n", result);
        return;
    }
}
void hkdf_extract(const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm, size_t ikm_len,
                  uint8_t *prk, size_t prk_len) {
    TCHmacState_t hmac;
    hmac = malloc(sizeof(struct tc_hmac_state_struct));
    tc_hmac_init(hmac);
    tc_hmac_set_key(hmac, salt, salt_len);
    tc_hmac_update(hmac, ikm, ikm_len);
    tc_hmac_final(prk, prk_len, hmac);
    free(hmac);
}

void hkdf_expand(const uint8_t *prk, size_t prk_len,
                 unsigned long *info, size_t info_len,
                 uint8_t *okm, size_t okm_len) {
    //size_t num_blocks = (okm_len + TC_SHA256_DIGEST_SIZE - 1) / TC_SHA256_DIGEST_SIZE;
    uint8_t key[TC_SHA256_DIGEST_SIZE];
    uint8_t *t = okm;
    size_t t_len = 0;
    uint8_t counter = 1;

    while (t_len < okm_len) {
        TCHmacState_t hmac;
        size_t len = (okm_len - t_len) > TC_SHA256_DIGEST_SIZE ? TC_SHA256_DIGEST_SIZE : (okm_len - t_len);

        hmac = malloc(sizeof(struct tc_hmac_state_struct));
        tc_hmac_init(hmac);
        tc_hmac_set_key(hmac, prk, prk_len);
        tc_hmac_update(hmac, t, t_len);
        tc_hmac_update(hmac, info, info_len);
        tc_hmac_update(hmac, &counter, sizeof(counter));
        tc_hmac_final(key, sizeof(key), hmac);
        free(hmac);

        memcpy(t + t_len, key, len);
        t_len += len;
        counter++;
    }
}
/*---------------------------------------------------------------------------*/
void hkdf(unsigned long timestamp) {
    uint8_t key[32];
    uint8_t prk[32];
    hkdf_extract(salt, sizeof(salt), device.secret_key, sizeof(device.secret_key), prk, sizeof(prk));
    hkdf_expand(prk, sizeof(prk), &timestamp, sizeof(timestamp), key, sizeof(key));

    uint8_t enc_key[16];
    int j = 0;
    for (int i = 0; i < 32; i++) {
        if (i == 0 || i == 1 || i == 4 || i == 5 || i == 8 || i == 9 || i == 12 || i == 13 || i == 16 || i == 17 
            || i == 20 || i == 21 || i == 24 || i == 25 || i == 28 || i == 29) {
            enc_key[j] = key[i];
            j++;
        }
    } 

    memcpy(device.current_key, enc_key, sizeof(enc_key));

    printf("KEY: ");
    for (size_t i = 0; i < sizeof(device.current_key); i++) {
        printf("%02x", device.current_key[i]);
    }
    printf("\n");
    initialize_AES(device.current_key);
}
/*---------------------------------------------------------------------------*/
void encrypt(const uint8_t *key, int key_size, uint8_t *ciphertext, int cipher_size) {

    const uint8_t associated_data[8] = {packet_number};
    int sensor_value = random_rand() % 51;
    uint8_t plaintext[16];

    snprintf((char*)plaintext, sizeof(plaintext) - 1, "Temp: %d", sensor_value);

    //printf("Plaintext value: %s\n", plaintext);

    int result;

    result = tc_ccm_config(ccm, ccm->sched, nonce, CCM_NONCE_SIZE, CCM_AUTH_SIZE);
    if (result != 1) {
        printf("CCM configs failed with error %d\n", result);
        return;
    }
    
    iv = 0;
    for (int i = 0; i < 5; i++) {
        iv = (iv << 8) | (random_rand() & 0xFF);
    }   
    // The 0xFF 'and' masks the generated value to keep only the 8 LSBs
    // Print the generated IV
    //printf("IV: %llx\n", iv);

    uip_ds6_addr_t *src_ipaddr = uip_ds6_get_link_local(-1);

    uint64_t ipv6_suffix = 0;
    for (int i = 0; i < 8; i++) {
        ipv6_suffix = (ipv6_suffix << 8) | src_ipaddr->ipaddr.u8[8 + i];
    }

    for (int i = 0; i < 8; i++) {
        nonce[i] = (ipv6_suffix >> (56 - i * 8)) & 0xFF;
    }
    for (int i = 0; i < 5; i++) {
        nonce[i + 8] = (iv >> (32 - i * 8)) & 0xFF;
    }

    result = tc_ccm_generation_encryption(ciphertext, cipher_size, associated_data,
                                    sizeof(associated_data), plaintext, sizeof(plaintext), ccm);
    if (result != 1) {
        printf("Encryption failed with error code %d\n", result);
        return;
    }

    /*printf("Plaintext: ");
    for (int i = 0; i < sizeof(plaintext); i++) {
    printf("%c", plaintext[i]);
    }
    printf("\n");

    printf("Sending ciphertext value: ");
    for (int i = 0; i < cipher_size; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");*/
}

static void reply_renew_key()
{
    if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {

        udp_packet_t packet;
        unsigned long timestamp = clock_time();
        hkdf_extract(salt, sizeof(salt), device.secret_key, sizeof(device.secret_key), device.prk, sizeof(device.prk));
        hkdf(timestamp);

        packet_number +=1;

        encrypt(device.current_key, sizeof(device.current_key), ciphertext, 24);

        for (int i = 0; i < 24; i++) {
            packet.payload[i] = ciphertext[i];
        }

        printf("Printing the sequence number: %u \n", packet_number);

        printf("Smart meter address:");
        uiplib_ipaddr_print(&dest_ipaddr);
        printf("\n");

        packet.sequence_number = packet_number;

        packet.partial_nonce = iv;

        packet.timestamp = timestamp;

        simple_udp_sendto(&unicast_conn, &packet, sizeof(packet), &dest_ipaddr);
    }
    //can_send = true;
}

static void sleep_mode(void *ptr)
{
    if (can_send){
        printf("Sleeping for the next for 6 seconds...\n");
        NETSTACK_RADIO.off();
    }
}

static void send_broadcast()
{
    if (can_send){
        NETSTACK_RADIO.on();
        reply_renew_key();
        printf("Listening for the next 4 seconds... \n");
        ctimer_set(&listening_timer, 4 * CLOCK_SECOND, sleep_mode, NULL);
    }
    /* Reset the timer for the next send */
    ctimer_reset(&broadcast_timer);
}

void decrypt(const uint8_t *key, int key_size, const uint8_t *ciphertext, int cipher_size, const uip_ipaddr_t *link_local_address){

    const uint8_t associated_data[8] = {packet_number};
    //uint8_t nonce[CCM_NONCE_SIZE] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b};
    
    /*
    printf("Ciphertext: ");
    for (int i = 0; i < 24; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");*/

    //tc_aes128_set_encrypt_key(ccm->sched, key);
    tc_ccm_config(ccm, ccm->sched, nonce, CCM_NONCE_SIZE, CCM_AUTH_SIZE);

    printf("Current KEY: ");
            for (int j = 0; j < 16; j++) {
                printf("%02x", key[j]);
            }
            printf("\n");

    uint8_t decrypted[16];
    int result = tc_ccm_decryption_verification(decrypted, sizeof(decrypted), associated_data, sizeof(associated_data), ciphertext, cipher_size, ccm);

    if (result != 1) {
        printf("Decryption failed with error code %d\n", result);
        return;
    }
    
    printf("Decrypted after receiving it: ");
    for (int i = 0; i < sizeof(decrypted); i++) {
        printf("%c", decrypted[i]);
    }
    printf("\n");

    if (strstr((char*)decrypted, "Added") != NULL) {
        can_send = true;
        memcpy(&smart_meter_address, link_local_address, sizeof(uip_ipaddr_t));
        printf("Smart Meter Link Local Address: ");
        uiplib_ipaddr_print(&smart_meter_address);
        printf("\n");
        send_broadcast();
    } /*else if (strstr((char*)decrypted, "Renew") != NULL){
        can_send = false;
        reply_renew_key("");
    }*/
}
/*---------------------------------------------------------------------------*/
static void broadcast_rx_callback(struct simple_udp_connection *c,
                                  const uip_ipaddr_t *sender_addr,
                                  uint16_t sender_port,
                                  const uip_ipaddr_t *receiver_addr,
                                  uint16_t receiver_port,
                                  const uint8_t *data,
                                  uint16_t datalen)
{
    udp_packet_t *received_packet = (udp_packet_t *)data;
    if (uip_ipaddr_cmp(&smart_meter_address, sender_addr)){
        for (int i = 0; i < 24; i++) {
        ciphertext[i] = received_packet->payload[i];
        }

        iv = received_packet->partial_nonce;

        uint64_t sender_suffix = 0;
        for (int i = 0; i < 8; i++) {
            sender_suffix = (sender_suffix << 8) | sender_addr->u8[8 + i];
        }

        for (int i = 0; i < 8; i++) {
            nonce[i] = (sender_suffix >> (56 - i * 8)) & 0xFF;
        }
        for (int i = 0; i < 5; i++) {
            nonce[i + 8] = (iv >> (32 - i * 8)) & 0xFF;
        }
        
        //decrypt(enc_key, sizeof(enc_key), ciphertext, 24, sender_addr);
    } else {
        //simple_udp_sendto(&broadcast_conn, &packet, sizeof(packet), &broadcast);
    }
    
    // Access the sequence number field
    //int sequence_number = received_packet->sequence_number;
    //printf("Printing the sequence number: %u \n", sequence_number);
}

static void unicast_rx_callback(struct simple_udp_connection *c,
                                  const uip_ipaddr_t *sender_addr,
                                  uint16_t sender_port,
                                  const uip_ipaddr_t *receiver_addr,
                                  uint16_t receiver_port,
                                  const uint8_t *data,
                                  uint16_t datalen)
{
    printf("Reached unicast \n");
    
    udp_packet_t *received_packet = (udp_packet_t *)data;

    for (int i = 0; i < 24; i++) {
        ciphertext[i] = received_packet->payload[i];
    }

    iv = received_packet->partial_nonce;

    printf("KEY: ");
    for (int j = 0; j < 16; j++) {
        printf("%02x", device.current_key[j]);
    }
    printf("\n");

    printf("Ciphertext: ");
    for (size_t i = 0; i < sizeof(ciphertext); i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    /*printf("Receiving ciphertext value: ");
    for (int i = 0; i < 24; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");*/
    //printf("Initialization Vector: %llx\n", iv);

    uint64_t sender_suffix = 0;
    for (int i = 0; i < 8; i++) {
        sender_suffix = (sender_suffix << 8) | sender_addr->u8[8 + i];
    }

    // Print the sender suffix
    printf("Sender Suffix: %llx\n", sender_suffix);

    for (int i = 0; i < 8; i++) {
        nonce[i] = (sender_suffix >> (56 - i * 8)) & 0xFF;
    }
    for (int i = 0; i < 5; i++) {
        nonce[i + 8] = (iv >> (32 - i * 8)) & 0xFF;
    }

    // Print the combined data
    printf("Nonce: ");
    for (int i = 0; i < 13; i++) {
        printf("%02x", nonce[i]);
    }
    printf("\n");

    packet_number = received_packet->sequence_number;
    
    decrypt(device.current_key, sizeof(device.current_key), ciphertext, 24, sender_addr);
}
/*---------------------------------------------------------------------------*/
PROCESS(hello_world_process, "Hello world process");
AUTOSTART_PROCESSES(&hello_world_process);
PROCESS_THREAD(hello_world_process, ev, data)
{

    PROCESS_BEGIN();

    /* Initialize BROADCAST connection */
    simple_udp_register(&broadcast_conn, 1234, NULL, 1234, broadcast_rx_callback);

    simple_udp_register(&unicast_conn, 5678, NULL, 5678, unicast_rx_callback);
    // ------------------------ Create broadcast address ------------------------
    uip_create_linklocal_allnodes_mcast(&broadcast);

    /*
    unsigned short test = 65;
    flash_write((unsigned short*)FLASH_ADDRESS, test);

    unsigned short stored_value = *((unsigned short*)FLASH_ADDRESS);

    printf("Stored value: %u\n", stored_value);
    */
    
    //long int max_value = __LONG_MAX__;

    //printf("Maximum value of int: %ld\n", max_value);
    
    // Print the timestamp in decimal
    
    ccm = malloc(sizeof(struct tc_ccm_mode_struct));
    ccm->sched = malloc(sizeof(struct tc_aes_key_sched_struct));
    memcpy(device.secret_key, ikm, sizeof(ikm));
    hkdf_extract(salt, sizeof(salt), device.secret_key, sizeof(device.secret_key), device.prk, sizeof(device.prk));
    hkdf(1);
    
    while(1) {
        ctimer_set(&broadcast_timer, 10 * CLOCK_SECOND, send_broadcast, NULL);
        //ctimer_set(&listening_timer, 5 * CLOCK_SECOND, listen_mode, NULL);
        PROCESS_YIELD();
    }

    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
