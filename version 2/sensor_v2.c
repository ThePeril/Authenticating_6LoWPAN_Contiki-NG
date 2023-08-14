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

uint8_t ciphertext[16+8]; 
uint8_t session_key[16];

TCCcmMode_t ccm;
uint8_t nonce[CCM_NONCE_SIZE];

const uint8_t ikm[32] = {0x3f, 0x9e, 0x76, 0x0f, 0xf5, 0xe9, 0xea, 0xf4, 0x19, 0x8d, 
                          0x0c, 0x02, 0xf1, 0x43, 0xf9, 0x57, 0x90, 0x4a, 0xca, 0x29, 0x73,
                          0x81, 0x2a, 0x93, 0xc1, 0x03, 0x5d, 0x46, 0x86, 0xd0, 0xa3, 0x32}; // the secret key

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
    uint64_t counter;
} device_t;
device_t device;
/*---------------------------------------------------------------------------*/
/* Function to set the key used for encryption and decryption for the AES-CCM encryption, decryption, and the generation and verification of the tag */ 
void initialize_AES(const uint8_t *key)
{
    int result;

    result = tc_aes128_set_encrypt_key(ccm->sched, key);
    if (result != 1) {
        printf("Key set failed!\n");
        return;
    }
}
/*---------------------------------------------------------------------------*/
/* Function to expand and derive cryptographic keys using SHA256, extraction is optional before that and hence is commented out */
void hkdf(unsigned long timestamp) 
{
    uint8_t okm[32];

    tc_hkdf_expand(ikm, &timestamp, sizeof(timestamp), 32, okm);

    int j = 0;
    for (int i = 0; i < 32; i++) { // reduce the key size to 128-bits and remove duplicates from the key
        if (i == 0 || i == 1 || i == 4 || i == 5 || i == 8 || i == 9 || i == 12 || i == 13 || i == 16 || i == 17 
            || i == 20 || i == 21 || i == 24 || i == 25 || i == 28 || i == 29) {
            session_key[j] = okm[i];
            j++;
        }
    } 

    initialize_AES(session_key);
}
/*---------------------------------------------------------------------------*/
/* Function to encrypt the sensor measurements with the packet number, AD and a buffer to save the resulting ciphertext */
void encrypt(uint8_t *ciphertext, int cipher_size) 
{
    uint8_t associated_data[sizeof(device.counter)];
    for (int i = 0; i < sizeof(device.counter); i++) {
        associated_data[i] = (device.counter >> (i * 8)) & 0xFF;
    }
    
    uint8_t plaintext[16];
    
    if (device.counter == 1){ // if this is the first message, then it's a request to add
        strncpy((char*)plaintext, "Request Add", sizeof(plaintext) - 1);
        plaintext[sizeof(plaintext) - 1] = '\0';
    } else { // otherwise it's a sensor measurement
        int sensor_value = random_rand() % 51; 
        snprintf((char*)plaintext, sizeof(plaintext) - 1, "Temp: %d C", sensor_value);
    }

    int result;

    uip_ds6_addr_t *src_ipaddr = uip_ds6_get_link_local(-1); // get own link-local IPv6 address

    uint64_t ipv6_suffix = 0;
    for (int i = 0; i < 8; i++) {
        ipv6_suffix = (ipv6_suffix << 8) | src_ipaddr->ipaddr.u8[8 + i];
    }

    uint64_t last_64_bits = ipv6_suffix & 0xFFFFFFFFFFFFFFFF; // keep the last 64-bits
    uint64_t counter_40_bits = device.counter & 0xFFFFFFFFFF; // keep the first 40-bits

    uint8_t nonce[13]; // combine the last 64-bits of the link local address and the first 40-bits of the device's counter into nonce
    for (int i = 0; i < 8; i++) {
        nonce[i] = (last_64_bits >> (56 - i * 8)) & 0xFF;
    }
    for (int i = 0; i < 5; i++) {
        nonce[8 + i] = (counter_40_bits >> (32 - i * 8)) & 0xFF;
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

        if (can_send){
            device.counter +=1;
        } else {
            device.counter = 1;
        }

        encrypt(ciphertext, 24);

        for (int i = 0; i < 24; i++) {
            packet.payload[i] = ciphertext[i];
        }

        packet.sequence_number = device.counter;

        packet.timestamp = timestamp;

        simple_udp_sendto(&unicast_conn, &packet, sizeof(packet), &dest_ipaddr);
        dont_sleep = false;
    } else {
        if (dont_sleep){ 
            // if this was reached twice, then there's a problem with the sync with other devices, so wait 1 second every time this is reached to try and become
            // in-sync with the other devices
            printf("Cannot reach root?\n");
            clock_wait(CLOCK_SECOND);
        }
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
/* Function to turn the radio transceiver on and call the sending the message and the sleep/wake up functions periodically */
static void send_sensor_measurements()
{
    NETSTACK_RADIO.on();
    renew_key_and_reply();
    ctimer_set(&send_measurements_timer, 60 * CLOCK_SECOND, send_sensor_measurements, NULL);
    if (can_send){
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
void decrypt(const uint8_t *ciphertext, int cipher_size)
{
    device.counter = 1;
    uint8_t associated_data[sizeof(device.counter)];
    for (int i = 0; i < sizeof(device.counter); i++) {
        associated_data[i] = (device.counter >> (i * 8)) & 0xFF;
    }
    
    tc_ccm_config(ccm, ccm->sched, nonce, CCM_NONCE_SIZE, CCM_AUTH_SIZE);

    uint8_t decrypted[16];
    int result = tc_ccm_decryption_verification(decrypted, sizeof(decrypted), associated_data, sizeof(associated_data), ciphertext, cipher_size, ccm);

    if (result != 1) {
        printf("Decryption failed!\n");
        return;
    }
    
    printf("Decrypted after receiving it: ");
    for (int i = 0; i < sizeof(decrypted); i++) {
        printf("%c", decrypted[i]);
    }
    printf("\n");

    if (strstr((char*)decrypted, "Added") != NULL) { // if it receives an "Added" message then it can send its sensor measurements now
        can_send = true;
        send_sensor_measurements();
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

    if (uip_ipaddr_cmp(&dest_ipaddr, &UIP_IP_BUF->srcipaddr) || received_packet->sequence_number < device.counter){
        for (int i = 0; i < 24; i++) {
            ciphertext[i] = received_packet->payload[i];
        }

        uint64_t ipv6_suffix = 0;
        for (int i = 0; i < 8; i++) {
            ipv6_suffix = (ipv6_suffix << 8) | sender_addr->u8[8 + i];
        }

        uint64_t last_64_bits = ipv6_suffix & 0xFFFFFFFFFFFFFFFF;
        uint64_t counter_40_bits = received_packet->sequence_number & 0xFFFFFFFFFF; 

        for (int i = 0; i < 8; i++) {
            nonce[i] = (last_64_bits >> (56 - i * 8)) & 0xFF;
        }
        for (int i = 0; i < 5; i++) {
            nonce[8 + i] = (counter_40_bits >> (32 - i * 8)) & 0xFF;
        }

        hkdf(received_packet->timestamp);

        decrypt(ciphertext, 24);
    } else {
        printf("Packet was rejected! \n");
    }
}
/*---------------------------------------------------------------------------*/
/* The main function, awaits messages on port 5678 and periodically call the send sensor measurements (once) and the stay awake function (60, 600 seconds respectively) */
PROCESS(hello_world_process, "Hello world process");
AUTOSTART_PROCESSES(&hello_world_process);
PROCESS_THREAD(hello_world_process, ev, data)
{

    PROCESS_BEGIN();

    simple_udp_register(&unicast_conn, 5678, NULL, 5678, unicast_rx_callback);
    
    ccm = malloc(sizeof(struct tc_ccm_mode_struct));
    ccm->sched = malloc(sizeof(struct tc_aes_key_sched_struct));

    device.counter = 0;
    ctimer_set(&send_measurements_timer, 60 * CLOCK_SECOND, send_sensor_measurements, NULL);
    while(1) {
        
        ctimer_set(&stay_awake_timer, 600 * CLOCK_SECOND, stay_awake, NULL);
        PROCESS_YIELD();
    }

    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
