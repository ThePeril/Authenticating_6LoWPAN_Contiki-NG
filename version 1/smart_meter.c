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
#include "dev/serial-line.h"
#include "cpu/msp430/dev/uart0.h"
/*---------------------------------------------------------------------------*/
#define CCM_AUTH_SIZE 8
#define CCM_NONCE_SIZE 13
#define MAX_DEVICES 7

static struct simple_udp_connection unicast_conn;

static struct ctimer check_reponse_timer;
static struct ctimer check_lost_messages_timer;
static struct ctimer listening_timer;

TCCcmMode_t ccm;
uint8_t nonce[CCM_NONCE_SIZE];
uint8_t session_key[16];
uint64_t iv;

typedef struct {
    unsigned long sequence_number;
    uint8_t payload[24];
    uint64_t partial_nonce;
    unsigned long timestamp;
} udp_packet_t;

typedef struct {
    uint8_t secret_key[32];
    uip_ipaddr_t link_local_address;
    bool filled;
    unsigned long sequence_number;
    int timeout_counter;
} device_t;

device_t device_list[MAX_DEVICES];

bool devices_are_listening = false;
bool send_first_unicast_again = false;
int send_first_unicast_number;
int number_of_devices = 0;
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
void hkdf(int device_number, unsigned long timestamp) 
{
    uint8_t okm[32];

    /*uint8_t salt[32] = {0x00}; // Optional key extraction by setting a salt and saving the value in prk
    uint8_t prk[32];
    tc_hkdf_extract(device_list[device_number].secret_key,32,salt,sizeof(salt),prk);*/

    tc_hkdf_expand(device_list[device_number].secret_key, &timestamp, sizeof(timestamp), 32, okm);

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
void encrypt(uint8_t *ciphertext, int cipher_size, unsigned long packet_number, char* msg_type) 
{
    uint8_t associated_data[sizeof(packet_number)];

    for (int i = 0; i < sizeof(packet_number); i++) { // convert the packet_number to uint8_t
        associated_data[i] = (packet_number >> (i * 8)) & 0xFF;
    }

    uint8_t plaintext[16];

    strncpy((char*)plaintext, msg_type, sizeof(plaintext) - 1);
    plaintext[sizeof(plaintext) - 1] = '\0'; // Null terminator for chars in C

    int result;

    iv = 0;
    for (int i = 0; i < 5; i++) { // generate random 5-byte IV
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

        encrypt(ciphertext, 24, 1, "Added");

        for (int i = 0; i < 24; i++) {
            packet.payload[i] = ciphertext[i];
        }

        packet.sequence_number = 1;

        packet.partial_nonce = iv;

        packet.timestamp = timestamp;

        /*printf("Session key used: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", device_list[device_number].current_key[i]);
        }
        printf("\n");

        printf("Timestamp to send: %lu \n", timestamp);

        printf("Ciphertext to send: ");
        for (int i = 0; i < 24; i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\n");

        printf("Device's packet sequence number: %lu\n", packet.sequence_number);

        printf("Nonce used: ");
        for (int i = 0; i < 13; i++) {
            printf("%02x", nonce[i]);
        }
        printf("\n");

        printf("Partial nonce (iv): %llx\n", iv);

        printf("Device %d - Link Local Address: ", device_number);
        uiplib_ipaddr_print(&device_list[device_number].link_local_address);
        printf("\n");*/

        device_list[device_number].sequence_number = 1;
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
/* Function to re-send the first unicast message to device that didn't receive it, called every 600 seconds */
static void check_lost_messages()
{
    for (int i = 0; i < MAX_DEVICES; i++){
        if (device_list[i].filled ){
            if (device_list[i].sequence_number == 1){
                send_first_unicast(i);
            }
        }
    }
    ctimer_reset(&check_lost_messages_timer);
}
/*---------------------------------------------------------------------------*/
/* Function to decrypt the received ciphertext given the device's sequence number */
void decrypt(const uint8_t *ciphertext, int cipher_size, int device_number, unsigned long sequence_number)
{
    uint8_t associated_data[sizeof(sequence_number)];

    for (int i = 0; i < sizeof(sequence_number); i++) {
        associated_data[i] = (sequence_number >> (i * 8)) & 0xFF;
    }
    
    int result;
	
    result = tc_ccm_config(ccm, ccm->sched, nonce, CCM_NONCE_SIZE, CCM_AUTH_SIZE);

    if (result != 1) {
        printf("CCM configs failed!\n");
        return;
    }

    uint8_t decrypted[16];
    result = tc_ccm_decryption_verification(decrypted, sizeof(decrypted), associated_data, sizeof(associated_data), ciphertext, cipher_size, ccm);

    if (result != 1) {
        printf("Decryption failed!\n");
        return;
    } else { // if decrypted successfully, then the devices are listening since they are assumed to be synchronized
        devices_are_listening = true;
        if (send_first_unicast_again){
            ctimer_set(&check_reponse_timer, 2 * CLOCK_SECOND, validate_addition, NULL);
            send_first_unicast_again = false;
        }
        ctimer_set(&listening_timer, 4.5 * CLOCK_SECOND, sleep_mode, NULL);
    }
    
    printf("%s\n", decrypted);
}
/*---------------------------------------------------------------------------*/
/* Function to check whether the received message comes from an authenticated device, and to timeout devices that have been silent for too long */
int device_saved(const uip_ipaddr_t *sender_address)
{
    for(int i = 0; i < MAX_DEVICES; i++){
        if (device_list[i].filled){
            if (uip_ipaddr_cmp(&device_list[i].link_local_address, sender_address)){
                device_list[i].timeout_counter = 0;
                return i;
            } else {
                device_list[i].timeout_counter += 1;
            }
            
            if (device_list[i].timeout_counter > 50){
                printf("Deleting timed out device\n");
                for (int j = i; j < MAX_DEVICES; j++){
                    device_list[j] = device_list[j+1];
                    device_list[j+1].filled = false;
                }
                number_of_devices -=1;
            }
        }
    }
    return -1;
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

    if (device_number != -1 && received_packet->sequence_number > device_list[device_number].sequence_number){ 
        // if device is authenticated, and its not a potential replay attack

        hkdf(device_number, received_packet->timestamp);

        uint8_t ciphertext[16+8]; 
        device_list[device_number].sequence_number = received_packet->sequence_number;
        
        for (int i = 0; i < 24; i++) {
            ciphertext[i] = received_packet->payload[i];
        }

        iv = received_packet->partial_nonce;

        printf("Device %d & Packet Number: %lu - Link Local Address: ", device_number, received_packet->sequence_number);
        uiplib_ipaddr_print(&device_list[device_number].link_local_address);
        printf("\n");

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
        
        decrypt(ciphertext, 24, device_number, device_list[device_number].sequence_number);
    } else {
        printf("Packet rejected, unauthenticated device or replay attack detected!\n");
    }
}
/*---------------------------------------------------------------------------*/
/* The following 2 functions convert the string from the serial interface into numerical hex (to be converted to uint8_t)*/
int convert_char_to_numerical_hex(char character) 
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    } else if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    } else if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return 0;
}
void convert_string_to_uint8(const char* hex_string, uint8_t* byte_array, size_t byte_array_size) 
{
    for (int i = 0; i < byte_array_size; i += 2) {
        byte_array[i / 2] = (convert_char_to_numerical_hex(hex_string[i]) << 4) | convert_char_to_numerical_hex(hex_string[i + 1]);
    }
}
/*---------------------------------------------------------------------------*/
/* The main function, initializes this node as an RPL root, awaits messages on port 5678 and await messages from the serial interface */
PROCESS(smart_meter_process, "Smart meter process");
AUTOSTART_PROCESSES(&smart_meter_process);
PROCESS_THREAD(smart_meter_process, ev, data)
{

    PROCESS_BEGIN();

    NETSTACK_ROUTING.root_start();

    simple_udp_register(&unicast_conn, 5678, NULL, 5678, unicast_rx_callback);

    serial_line_init();
    uart0_set_input(serial_line_input_byte);

    ccm = malloc(sizeof(struct tc_ccm_mode_struct));
    ccm->sched = malloc(sizeof(struct tc_aes_key_sched_struct));

    while(1) {
        if (ev == serial_line_event_message && data != NULL) {
            char *token = strtok((char *)data, "/"); // first part is the link-local address
            uip_ipaddr_t link_local_address;
            if (uiplib_ipaddrconv(token, &link_local_address)) { // second part of the string is the device's secret key
                token = strtok(NULL, "/");
                if (token != NULL) {
                    if (strlen(token) == 64 && number_of_devices < MAX_DEVICES){
                        convert_string_to_uint8(token, device_list[number_of_devices].secret_key, 64);
                        memcpy(&device_list[number_of_devices].link_local_address, &link_local_address, sizeof(uip_ipaddr_t));
                        device_list[number_of_devices].filled = true;
                        send_first_unicast(number_of_devices);
                        number_of_devices+=1;
                    } else {
                        printf("Invalid key size entered, or max. number of devices reached.\n");
                    }
                }            
            } else {
                printf("Invalid IPv6 address: %s\n", (char*) data);
            }
        }
        ctimer_set(&check_lost_messages_timer, 600 * CLOCK_SECOND, check_lost_messages, NULL);
        PROCESS_YIELD();
    }

    free(ccm);
    free(ccm->sched);
    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
