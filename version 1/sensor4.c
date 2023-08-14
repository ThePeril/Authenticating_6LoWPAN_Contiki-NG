#include "contiki.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "aes.h"
#include "ccm_mode.h"
#include "hkdf.h"
#include "random.h"
#include "uiplib.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/simple-udp.h"
#include "dev/flash.h"
#include "net/netstack.h"
#include "os/net/nullnet/nullnet.h"
#include "net/routing/routing.h"
/*---------------------------------------------------------------------------*/
#define CCM_AUTH_SIZE 8
#define CCM_NONCE_SIZE 13

uip_ipaddr_t dest_ipaddr;

static struct simple_udp_connection unicast_conn;

static struct ctimer send_measurements_timer;
static struct ctimer listening_timer;
static struct ctimer stay_awake_timer;
static struct ctimer waking_up_timer;

uint8_t ciphertext[16+8]; 

TCCcmMode_t ccm;
uint8_t nonce[CCM_NONCE_SIZE];
uint64_t iv;

const uint8_t ikm[32] = {0xde, 0xb6, 0x5c, 0xd6, 0xe0, 0x35, 0x64, 0x31, 0x48, 0xf9, 0x3a, 0x09, 0xb9, 0x2a, 0x7a, 0x90, 
0x00, 0x5a, 0xe0, 0x0e, 0x50, 0xa9, 0xac, 0x20, 0x3c, 0xf2, 0xb3, 0x4e, 0x77, 0xf9, 0x48, 0x47}; // the secret key

unsigned long packet_number = 1;

bool can_send = false;
bool dont_sleep = false;
bool must_stay_awake = false;

typedef struct {
    unsigned long sequence_number;
    uint8_t payload[24];
    uint64_t partial_nonce;
    unsigned long timestamp;
} udp_packet_t;

typedef struct {
    uint8_t current_key[16];
    uip_ipaddr_t link_local_address;
} device_t;
device_t device;
/*---------------------------------------------------------------------------*/
/* Function to set the key used for encryption and decryption for the AES-CCM encryption, decryption, and the generation and verification of the tag */ 
void initialize_AES(const uint8_t *key){
    int result;

    result = tc_aes128_set_encrypt_key(ccm->sched, key);
    if (result != 1) {
        printf("Key set failed!\n");
        return;
    }
}
/*---------------------------------------------------------------------------*/
/* Function to expand and derive cryptographic keys using SHA256, extraction is optional before that and hence is commented out */
void hkdf(unsigned long timestamp) {
    uint8_t okm[32];

    /* const uint8_t salt[] = {0x00}; // Optional key extraction by setting a salt and saving the value in prk
    uint8_t prk[32];
    tc_hkdf_extract(ikm,32,salt,sizeof(salt),prk);*/

    tc_hkdf_expand(ikm, &timestamp, sizeof(timestamp), 32, okm);

    int j = 0;
    for (int i = 0; i < 32; i++) {
        if (i == 0 || i == 1 || i == 4 || i == 5 || i == 8 || i == 9 || i == 12 || i == 13 || i == 16 || i == 17 
            || i == 20 || i == 21 || i == 24 || i == 25 || i == 28 || i == 29) {
            device.current_key[j] = okm[i];
            j++;
        }
    } 

    initialize_AES(device.current_key);
}
/*---------------------------------------------------------------------------*/
/* Function to encrypt the sensor measurements with the packet number, AD and a buffer to save the resulting ciphertext */
void encrypt(uint8_t *ciphertext, int cipher_size) {

    uint8_t associated_data[sizeof(packet_number)];

    for (int i = 0; i < sizeof(packet_number); i++) {
        associated_data[i] = (packet_number >> (i * 8)) & 0xFF;
    }
    int sensor_value = random_rand() % 61;
    uint8_t plaintext[16];

    snprintf((char*)plaintext, sizeof(plaintext) - 1, "Dist.: %d m", sensor_value);

    int result;

    iv = 0;
    for (int i = 0; i < 5; i++) {  // generate random 5-byte IV
        iv = (iv << 8) | (random_rand() & 0xFF);
    }   

    uip_ds6_addr_t *src_ipaddr = uip_ds6_get_link_local(-1); // get own link-local IPv6 address

    uint64_t ipv6_suffix = 0; 
    for (int i = 0; i < 8; i++) { // assign the last 64 bits of the IPv6 link-local address to the ipv6_suffix
        ipv6_suffix = (ipv6_suffix << 8) | src_ipaddr->ipaddr.u8[8 + i];
    }

    for (int i = 0; i < 8; i++) { // assign the first 8 bytes of the nonce from the ipv6_suffix
        nonce[i] = (ipv6_suffix >> (56 - i * 8)) & 0xFF;
    }
    for (int i = 0; i < 5; i++) { // assign the last 5 bytes of the nonce from the generated random iv
        nonce[i + 8] = (iv >> (32 - i * 8)) & 0xFF;
    }

    result = tc_ccm_config(ccm, ccm->sched, nonce, CCM_NONCE_SIZE, CCM_AUTH_SIZE);
    if (result != 1) {
        printf("CCM configs failed!\n");
        return;
    }

    result = tc_ccm_generation_encryption(ciphertext, cipher_size, associated_data,
                                    sizeof(associated_data), plaintext, sizeof(plaintext), ccm);
    if (result != 1) {
        printf("Encryption failed!\n");
        return;
    }
}
/*---------------------------------------------------------------------------*/
/* Function to derive a session key and encrypt sensor measurements then send it to the root node */
static void renew_key_and_reply()
{
    if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {

        udp_packet_t packet;
        unsigned long timestamp = clock_time();
        hkdf(timestamp);

        packet_number +=1;

        encrypt(ciphertext, 24);

        for (int i = 0; i < 24; i++) {
            packet.payload[i] = ciphertext[i];
        }

        packet.sequence_number = packet_number;

        packet.partial_nonce = iv;

        packet.timestamp = timestamp;

        simple_udp_sendto(&unicast_conn, &packet, sizeof(packet), &dest_ipaddr);
        dont_sleep = false;
    } else {
        printf("Can't reach root! \n");
        dont_sleep = true;
    }
}
/*---------------------------------------------------------------------------*/
/* Function to turn off the radio transceiver to save computer resources, is called periodically */
static void sleep_mode(void *ptr)
{
    if (can_send && !dont_sleep && !must_stay_awake){
        NETSTACK_RADIO.off();
    }
}
/*---------------------------------------------------------------------------*/
/* Function to tell the device to stay awake to have a longer listening cycle */
static void stay_awake()
{
    must_stay_awake = true;
    ctimer_reset(&stay_awake_timer);
}
/*---------------------------------------------------------------------------*/
/* Function call the reply function to send the sensor measurements, is called periodically */
static void waking_up()
{
    renew_key_and_reply();
}
/*---------------------------------------------------------------------------*/
/* Function to turn the radio transceiver on and call the sending the message and the sleep/wake up functions periodically */
static void send_sensor_measurements()
{
    if (can_send){
        NETSTACK_RADIO.on();
        ctimer_set(&waking_up_timer, 2 * CLOCK_SECOND, waking_up, NULL);
        if (must_stay_awake){
            must_stay_awake = false;
            ctimer_set(&listening_timer, 30 * CLOCK_SECOND, sleep_mode, NULL);
        } else {
            ctimer_set(&listening_timer, 5 * CLOCK_SECOND, sleep_mode, NULL);
        }
    }
    ctimer_reset(&send_measurements_timer);
}
/*---------------------------------------------------------------------------*/
/* Function to decrypt the received ciphertext */
void decrypt(const uint8_t *ciphertext, int cipher_size, const uip_ipaddr_t *link_local_address){

    uint8_t associated_data[sizeof(packet_number)];

    for (int i = 0; i < sizeof(packet_number); i++) {
        associated_data[i] = (packet_number >> (i * 8)) & 0xFF;
    }

    int result = tc_ccm_config(ccm, ccm->sched, nonce, CCM_NONCE_SIZE, CCM_AUTH_SIZE);

    if (result != 1) {
        printf("CCM configs failed!\n");
        return;
    }

    uint8_t decrypted[16];
    result = tc_ccm_decryption_verification(decrypted, sizeof(decrypted), associated_data, sizeof(associated_data), ciphertext, cipher_size, ccm);

    if (result != 1) {
        printf("Decryption failed!\n");
        return;
    }
    
    printf("Decrypted after receiving it: ");
    for (int i = 0; i < sizeof(decrypted); i++) {
        printf("%c", decrypted[i]);
    }
    printf("\n");

    if (strstr((char*)decrypted, "Added") != NULL) {
        can_send = true;
    }
}
/*---------------------------------------------------------------------------*/
/* Callback function called automatically when a message is received on the unicast port (5678), and it analyzes the received packet to be decrypted */
static void unicast_rx_callback(struct simple_udp_connection *c,
                                  const uip_ipaddr_t *sender_addr,
                                  uint16_t sender_port,
                                  const uip_ipaddr_t *receiver_addr,
                                  uint16_t receiver_port,
                                  const uint8_t *data,
                                  uint16_t datalen)
{
    NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr);
    udp_packet_t *received_packet = (udp_packet_t *)data;
    if (uip_ipaddr_cmp(&dest_ipaddr, &UIP_IP_BUF->srcipaddr) || received_packet->sequence_number < packet_number){
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

        packet_number = received_packet->sequence_number;
        hkdf(received_packet->timestamp);

        /*printf("Session key used: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", device.current_key[i]);
        }
        printf("\n");

        printf("Timestamp received: %lu \n", received_packet->timestamp);

        printf("Ciphertext received: ");
        for (int i = 0; i < 24; i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\n");

        printf("Device's packet sequence number: %lu\n", received_packet->sequence_number);

        printf("Nonce used: ");
        for (int i = 0; i < 13; i++) {
            printf("%02x", nonce[i]);
        }
        printf("\n");

        printf("Partial nonce (iv) received: %llx\n", iv);

        printf("Received from root device - Link Local Address: ");
        uiplib_ipaddr_print(&dest_ipaddr);
        printf("\n");*/

        decrypt(ciphertext, 24, sender_addr);
    } else {
        printf("Packet was rejected! \n");
    }
}
/*---------------------------------------------------------------------------*/
/* The main function, awaits messages on port 5678 and periodically call the send sensor measurements and the stay awake function (60, 600 seconds respectively) */
PROCESS(hello_world_process, "Hello world process");
AUTOSTART_PROCESSES(&hello_world_process);
PROCESS_THREAD(hello_world_process, ev, data)
{

    PROCESS_BEGIN();

    simple_udp_register(&unicast_conn, 5678, NULL, 5678, unicast_rx_callback);
    
    ccm = malloc(sizeof(struct tc_ccm_mode_struct));
    ccm->sched = malloc(sizeof(struct tc_aes_key_sched_struct));

    while(1) {
        ctimer_set(&send_measurements_timer, 60 * CLOCK_SECOND, send_sensor_measurements, NULL);
        ctimer_set(&stay_awake_timer, 600 * CLOCK_SECOND, stay_awake, NULL);
        PROCESS_YIELD();
    }

    free(ccm);
    free(ccm->sched);

    PROCESS_END();
}
/*---------------------------------------------------------------------------*/