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
#include "net/routing/routing.h"
/*---------------------------------------------------------------------------*/
#define CCM_AUTH_SIZE 8
#define CCM_NONCE_SIZE 13
#define MAX_DEVICES 7

static struct simple_udp_connection unicast_conn;

TCCcmMode_t ccm;
uint8_t nonce[CCM_NONCE_SIZE];
uint64_t iv;
typedef struct {
    unsigned long sequence_number;
    uint8_t payload[24];
    uint64_t partial_nonce;
    unsigned long timestamp;
} udp_packet_t;
const uint8_t ikm[32] = {0x3f, 0x9e, 0x76, 0x0f, 0xf5, 0xe9, 0xea, 0xf4, 0x19, 0x8d, 
                          0x0c, 0x02, 0xf1, 0x43, 0xf9, 0x57, 0x90, 0x4a, 0xca, 0x29, 0x73,
                          0x81, 0x2a, 0x93, 0xc1, 0x03, 0x5d, 0x46, 0x86, 0xd0, 0xa3, 0x32}; // the secret key
typedef struct {
    uip_ipaddr_t link_local_address;
    bool filled;
    bool is_listening;
    uint64_t counter;
} device_t;
device_t device_list[MAX_DEVICES];

int number_of_devices = 0;
int fail_count = 0;

static struct ctimer listening_timer;
static struct ctimer reset_blocked_timer;
static struct ctimer check_reponse_timer;

uip_ipaddr_t potential_spam_address;
uip_ipaddr_t blocked_address;

bool potential_add = false;
bool send_first_unicast_again = false;
bool devices_are_listening = false;

int send_first_unicast_number;

uint8_t session_key[16];
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
void hkdf(int device_number, unsigned long timestamp) {
    uint8_t okm[32];
    
    /*uint8_t salt[32] = {0x00}; 
    uint8_t prk[32];
    tc_hkdf_extract(ikm,32,salt,sizeof(salt),prk);*/

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
/* Function to encrypt a message given a packet number as AD and a buffer to save the resulting ciphertext */
void encrypt(uint8_t *ciphertext, int cipher_size, int packet_number, char* msg_type, int device_number) {

    uint8_t associated_data[sizeof(device_list[device_number].counter)]; 
    for (int i = 0; i < sizeof(device_list[device_number].counter); i++) { // convert the device counter to uint8_t
        associated_data[i] = (device_list[device_number].counter >> (i * 8)) & 0xFF;
    }
    uint8_t plaintext[16];

    strncpy((char*)plaintext, msg_type, sizeof(plaintext) - 1);
    plaintext[sizeof(plaintext) - 1] = '\0'; // Null terminator for chars in C

    int result;

    uip_ds6_addr_t *src_ipaddr = uip_ds6_get_link_local(-1); // get own link-local IPv6 address

    uint64_t ipv6_suffix = 0;
    for (int i = 0; i < 8; i++) {
        ipv6_suffix = (ipv6_suffix << 8) | src_ipaddr->ipaddr.u8[8 + i];
    }

    uint64_t last_64_bits = ipv6_suffix & 0xFFFFFFFFFFFFFFFF;  // keep the last 64-bits
    uint64_t counter_40_bits = device_list[device_number].counter & 0xFFFFFFFFFF; // keep the first 40-bits

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
/* Function to send a unicasted message to the authenticated device */
static void send_first_unicast(int device_number)
{
    if (device_number > 0 && !devices_are_listening){ // if devices are sleeping, wait for them to wake up then send again with the help of these 2 variables
        send_first_unicast_again = true;
        send_first_unicast_number = device_number;
    } else {
        udp_packet_t packet;
        uint8_t ciphertext[16+8]; 

        unsigned long timestamp = clock_time();
        hkdf(device_number, timestamp);
        
        device_list[device_number].counter = 1;

        encrypt(ciphertext, 24, 1, "Added", device_number);

        for (int i = 0; i < 24; i++) {
            packet.payload[i] = ciphertext[i];
        }

        packet.sequence_number = 1;

        packet.timestamp = timestamp;

        device_list[device_number].counter = 1;
        simple_udp_sendto(&unicast_conn, &packet, sizeof(packet), &device_list[device_number].link_local_address);
    }
}
/*---------------------------------------------------------------------------*/
/* Function to call the sending first unicast function after a certain period */
static void validate_addition()
{
    send_first_unicast(send_first_unicast_number);
}
/*---------------------------------------------------------------------------*/
/* Function to set the status of the device to sleeping after 4.5 seconds */
static void sleep_mode(void *ptr)
{
    devices_are_listening = false;
}
/*---------------------------------------------------------------------------*/
/* Function to decrypt the received ciphertext given the device's sequence number */
void decrypt(const uint8_t *ciphertext, int cipher_size, int device_number){

    uint8_t associated_data[sizeof(device_list[device_number].counter)];
    for (int i = 0; i < sizeof(device_list[device_number].counter); i++) {
        associated_data[i] = (device_list[device_number].counter >> (i * 8)) & 0xFF;
    }
    
    tc_ccm_config(ccm, ccm->sched, nonce, CCM_NONCE_SIZE, CCM_AUTH_SIZE);

    uint8_t decrypted[16];
    int result = tc_ccm_decryption_verification(decrypted, sizeof(decrypted), associated_data, sizeof(associated_data), ciphertext, cipher_size, ccm);

    if (result != 1) {
        printf("Decryption failed!\n");
        if (potential_add){ // if the first decryption fails, remove the device from device's list or add to the fail count
            //device_list[device_number].filled = false;
            number_of_devices -=1;
            potential_add = false;
            fail_count += 1;
            memcpy(&potential_spam_address, &device_list[device_number].link_local_address, sizeof(uip_ipaddr_t));
        }
        return;
    } else { // if decryption was successful, and it's a request for addition, then send first unicast and sleep status after 4.5 seconds, 
    // otherwise just set the sleep and check if there are any pending devices that require additions
        if (potential_add){
            potential_add = false;
            if (strstr((char*)decrypted, "Request Add") != NULL){
                if (number_of_devices <= 1 || (number_of_devices > 1 && devices_are_listening)){
                    send_first_unicast(device_number);
                    devices_are_listening = true;
                    ctimer_set(&listening_timer, 4.5 * CLOCK_SECOND, sleep_mode, NULL);
                } else if (!devices_are_listening){
                    send_first_unicast_again = true;
                    send_first_unicast_number = device_number;
                }
            }
        } else {
            if (send_first_unicast_again){
                ctimer_set(&check_reponse_timer, 2 * CLOCK_SECOND, validate_addition, NULL);
                send_first_unicast_again = false;
            }
            ctimer_set(&listening_timer, 4.5 * CLOCK_SECOND, sleep_mode, NULL);
            devices_are_listening = true;
        }
    }
    
    printf("%s\n", decrypted);
}
/*---------------------------------------------------------------------------*/
/* Function to check whether the received message comes from an authenticated device */
int device_saved(const uip_ipaddr_t *sender_address){   

    for(int i = 0; i < MAX_DEVICES; i++){
        if (device_list[i].filled){
            if (uip_ipaddr_cmp(&device_list[i].link_local_address, sender_address)){
                return i;
            }
        }
    }
    return -1;
}
/*---------------------------------------------------------------------------*/
/* Function to reset blocked address periodically every 600 seconds */
void reset_blocked_addresses(){
    uip_ipaddr_t temporary_empty_address;
    uip_ipaddr(&temporary_empty_address, 0, 0, 0, 0);
    memcpy(&blocked_address, &temporary_empty_address, sizeof(uip_ipaddr_t));
    fail_count = 0;
    ctimer_reset(&reset_blocked_timer);
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

    udp_packet_t *received_packet = (udp_packet_t *)data;
    int device_number = device_saved(&UIP_IP_BUF->srcipaddr);

    if (uip_ipaddr_cmp(&UIP_IP_BUF->srcipaddr, &potential_spam_address) && fail_count >= 5){ 
        // if the packet is from a spam address, and the fail count is above 5, then this device is potentially trying to DoS, so block it
        printf("Blocking this address!\n");
        memcpy(&blocked_address, &potential_spam_address, sizeof(uip_ipaddr_t));
    }
    if (device_number == -1 && number_of_devices < MAX_DEVICES && !uip_ipaddr_cmp(&UIP_IP_BUF->srcipaddr, &blocked_address)){
        // if the device was found, and the maximum number of devices isn't reached, and it's not a blocked address, then temporarily add this device to the device list
        device_number = number_of_devices;
        number_of_devices +=1;
        potential_add = true;
        device_list[device_number].filled = true;
        memcpy(&device_list[device_number].link_local_address, sender_addr, sizeof(uip_ipaddr_t));
    }
    if (!uip_ipaddr_cmp(&UIP_IP_BUF->srcipaddr, &blocked_address) && received_packet->sequence_number > device_list[device_number].counter){
        // if the address is not blocked and the sequence number is not lower than the last message, then process the packet
        hkdf(device_number, received_packet->timestamp);

        uint8_t ciphertext[16+8]; 
        device_list[device_number].counter = received_packet->sequence_number;
        
        for (int i = 0; i < 24; i++) {
            ciphertext[i] = received_packet->payload[i];
        }

        uint64_t sender_suffix = 0;
        for (int i = 0; i < 8; i++) {
        sender_suffix = (sender_suffix << 8) | sender_addr->u8[8 + i];
        }

        uint64_t last_64_bits = sender_suffix & 0xFFFFFFFFFFFFFFFF;
        uint64_t counter_40_bits = device_list[device_number].counter & 0xFFFFFFFFFF; 

        for (int i = 0; i < 8; i++) {
            nonce[i] = (last_64_bits >> (56 - i * 8)) & 0xFF;
        }
        for (int i = 0; i < 5; i++) {
            nonce[8 + i] = (counter_40_bits >> (32 - i * 8)) & 0xFF;
        }

        /*
        printf("Here's the src address: ");
        uiplib_ipaddr_print(&UIP_IP_BUF->srcipaddr);
        printf("\n");
        
        printf("Received packet number: %lu / From Device: %u\n", received_packet->sequence_number, device_number);

        printf("Key for this device is: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", device_list[device_number].current_key[i]);
        }
        printf("\n");
        printf("Received Ciphertext: ");
        for (int i = 0; i < sizeof(ciphertext); i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\n");
        printf("Nonce: ");
        for (int i = 0; i < 13; i++) {
            printf("%02x", nonce[i]);
        }
        printf("\n");*/
        
        decrypt(ciphertext, 24, device_number);
    } else {
        printf("This address is blocked or a potential replay attack is detected from: ");
        uiplib_ipaddr_print(&UIP_IP_BUF->srcipaddr);
        printf("\n");
    }
}
/*---------------------------------------------------------------------------*/
/* The main function, awaits messages on port 5678 and periodically call the reset blocked addresses function every 600 seconds */
PROCESS(smart_meter_process, "Smart meter process");
AUTOSTART_PROCESSES(&smart_meter_process);
PROCESS_THREAD(smart_meter_process, ev, data)
{

    PROCESS_BEGIN();

    NETSTACK_ROUTING.root_start();

    simple_udp_register(&unicast_conn, 5678, NULL, 5678, unicast_rx_callback);

    ccm = malloc(sizeof(struct tc_ccm_mode_struct));
    ccm->sched = malloc(sizeof(struct tc_aes_key_sched_struct));

    while(1) {
        ctimer_set(&reset_blocked_timer, 600 * CLOCK_SECOND, reset_blocked_addresses, NULL);
        PROCESS_YIELD();
    }

    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
