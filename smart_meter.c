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
#include "net/routing/routing.h"
#include "dev/flash.h"
#include "dev/serial-line.h"
#include "cpu/msp430/dev/uart0.h"
//#define FLASH_ADDRESS 0x1000
/*---------------------------------------------------------------------------*/
static struct simple_udp_connection broadcast_conn;
static struct simple_udp_connection unicast_conn;

//static uip_ipaddr_t broadcast;

//static struct ctimer broadcast_timer;
static struct ctimer check_reponse_timer;
//static struct ctimer listening_timer;

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define CCM_AUTH_SIZE 8
#define CCM_NONCE_SIZE 13

TCCcmMode_t ccm;
uint8_t nonce[CCM_NONCE_SIZE];
uint64_t iv;
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
    bool filled;
    bool is_listening;
    int sequence_number;
} device_t;
device_t device_list[3];

int packet_number = 1;
int number_of_devices = 0;

const uint8_t salt[32] = {0x00}; 
const uint8_t info[] = {1};

static struct ctimer listening_timers[3];

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
    uint8_t key[32];
    uint8_t *t = okm;
    size_t t_len = 0;
    uint8_t counter = 1;

    while (t_len < okm_len) {
        TCHmacState_t hmac;
        size_t len = (okm_len - t_len) > 32 ? 32 : (okm_len - t_len);

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
void hkdf(int device_number, unsigned long timestamp) {
    uint8_t key[32];
    uint8_t prk[32];
    hkdf_extract(salt, sizeof(salt), device_list[device_number].secret_key, sizeof(device_list[device_number].secret_key), prk, sizeof(prk));
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

    memcpy(device_list[device_number].current_key, enc_key, sizeof(enc_key));

    //initialize_AES(device_list[device_number].current_key);
}

void encrypt(const uint8_t *key, int key_size, uint8_t *ciphertext, int cipher_size, int packet_number, char* msg_type) {

    uint8_t associated_data[8] = {packet_number};
    uint8_t plaintext[16];

    strncpy((char*)plaintext, msg_type, sizeof(plaintext) - 1);
    plaintext[sizeof(plaintext) - 1] = '\0';
    //uint8_t nonce[CCM_NONCE_SIZE] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b};

    int result;

    initialize_AES(key);

    printf("Current KEY: ");
            for (int j = 0; j < 16; j++) {
                printf("%02x", key[j]);
            }
            printf("\n");

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
}

static void send_first_unicast(int device_number)
{
    udp_packet_t packet;
    uint8_t ciphertext[16+8]; 

    /*printf("Here's the receiver address: ");
    uiplib_ipaddr_print(&device_list[device_number].link_local_address);
    printf("\n");*/

    hkdf_extract(salt, sizeof(salt), device_list[device_number].secret_key, sizeof(device_list[device_number].secret_key), 
    device_list[device_number].prk, sizeof(device_list[device_number].prk));
    hkdf(device_number, 1);

    initialize_AES(device_list[device_number].current_key);
    
    /*printf("KEY: ");
    for (int i = 0; i < 16; i++) {
            printf("%02x", device_list[device_number].current_key[i]);
        }
    printf("\n");*/

    encrypt(device_list[device_number].current_key, sizeof(device_list[device_number].current_key), ciphertext, 24, 1, "Added");

    for (int i = 0; i < 24; i++) {
        packet.payload[i] = ciphertext[i];
    }

    packet.sequence_number = 1;

    packet.partial_nonce = iv;

    packet.timestamp = 0;

    /*printf("Device %d - Link Local Address: ", device_number);
    uiplib_ipaddr_print(&device_list[device_number].link_local_address);
    printf("\n");*/
    device_list[device_number].sequence_number = 1;
    printf("Reached before send \n");
    // Use Contiki-NG's built-in unicast_send to send the packet
    simple_udp_sendto(&unicast_conn, &packet, sizeof(packet), &device_list[device_number].link_local_address);
    printf("Reached after send \n");
}

static void validate_addition()
{
    for (int i = 0; i < 3; i++){
        if (device_list[i].filled && device_list[i].sequence_number == 1){
            printf("Sequence number of the device %u\n", device_list[i].sequence_number);
            send_first_unicast(i);
        }
    }
    //ctimer_reset(&check_reponse_timer);
}

static void sleep_mode(void *ptr)
{
    int *device_num_ptr = (int *)ptr;
    int device_num = *device_num_ptr;
    device_list[device_num].is_listening = false;
    printf("Device %d is sleeping...\n", device_num);
    free(device_num_ptr);
}

void decrypt(const uint8_t *key, int key_size, const uint8_t *ciphertext, int cipher_size, int device_number){

    uint8_t associated_data[8] = {packet_number};
    initialize_AES(key);
    
    tc_ccm_config(ccm, ccm->sched, nonce, CCM_NONCE_SIZE, CCM_AUTH_SIZE);

    uint8_t decrypted[16];
    int result = tc_ccm_decryption_verification(decrypted, sizeof(decrypted), associated_data, sizeof(associated_data), ciphertext, cipher_size, ccm);

    if (result != 1) {
        printf("Decryption failed with error code %d\n", result);
        return;
    } else {
        int *device_num_copy = (int *)malloc(sizeof(int));
        device_list[device_number].is_listening = true;
        printf("Device %d is listening...\n", device_number);
        *device_num_copy = device_number;
        // 3.5 and not 4 for transmission / receiving delay
        ctimer_set(&listening_timers[device_number], 3.5 * CLOCK_SECOND, sleep_mode, device_num_copy);
        ctimer_set(&check_reponse_timer, 1 * CLOCK_SECOND, validate_addition, NULL);
    }
    
    printf("%s\n", decrypted);
}
/*---------------------------------------------------------------------------*/
int device_saved(const uip_ipaddr_t *sender_address){
    for(int i = 0; i < 3; i++){
        if (device_list[i].filled){
            if (uip_ipaddr_cmp(&device_list[i].link_local_address, sender_address)){
                printf("Device %d - Link Local Address: ", i);
                uiplib_ipaddr_print(sender_address);
                printf("\n");
                return i;
            }
        }
    }
    return -1;
}
static void broadcast_rx_callback(struct simple_udp_connection *c,
                                  const uip_ipaddr_t *sender_addr,
                                  uint16_t sender_port,
                                  const uip_ipaddr_t *receiver_addr,
                                  uint16_t receiver_port,
                                  const uint8_t *data,
                                  uint16_t datalen)
{
    udp_packet_t *received_packet = (udp_packet_t *)data;

    int device_number = device_saved(sender_addr);
    if (device_number != -1){
        
        uint8_t ciphertext[16+8]; 
        packet_number = received_packet->sequence_number;
        //printf("Printing the sequence number: %u \n", packet_number);
        
        for (int i = 0; i < 24; i++) {
            ciphertext[i] = received_packet->payload[i];
        }

        iv = received_packet->partial_nonce;

        /*printf("Key for this device is: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", device_list[device_number].current_key[i]);
        }
        printf("\n");
        printf("Received Ciphertext: ");
        for (int i = 0; i < sizeof(ciphertext); i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\n");*/

        uint64_t sender_suffix = 0;
        for (int i = 0; i < 8; i++) {
            sender_suffix = (sender_suffix << 8) | sender_addr->u8[8 + i];
        }
        //printf("Sender Suffix: %llx\n", sender_suffix);

        for (int i = 0; i < 8; i++) {
            nonce[i] = (sender_suffix >> (56 - i * 8)) & 0xFF;
        }
        for (int i = 0; i < 5; i++) {
            nonce[i + 8] = (iv >> (32 - i * 8)) & 0xFF;
        }

        /*printf("Nonce: ");
        for (int i = 0; i < 13; i++) {
            printf("%02x", nonce[i]);
        }
        printf("\n");*/
        
        decrypt(device_list[device_number].current_key, 16, ciphertext, 24, device_number);
    }
    //fd00::c30c:0:0:1/3d9e760ff5e9eaf4198d0c02f143f957904aca2973812a93c1035d4686d0a332
    //fd00::c30c:0:0:2/70fb4664f46f0ea0317515e14075bdde5f90801b6ff69741db9af069d730e14e
    //fd00::c30c:0:0:4/d0f0bb8e3c83e5231705326834dd2934ae9a799b42d4330e5c5529717a52d7e8
    //fd00::c30c:0:0:5/deb65cd6e035643148f93a09b92a7a90005ae00e50a9ac203cf2b34e77f94847
}

static void unicast_rx_callback(struct simple_udp_connection *c,
                                  const uip_ipaddr_t *sender_addr,
                                  uint16_t sender_port,
                                  const uip_ipaddr_t *receiver_addr,
                                  uint16_t receiver_port,
                                  const uint8_t *data,
                                  uint16_t datalen)
{
    udp_packet_t *received_packet = (udp_packet_t *)data;

    printf("Here's the src address: ");
	 uiplib_ipaddr_print(&UIP_IP_BUF->srcipaddr);
	 printf("\n");
    int device_number = device_saved(&UIP_IP_BUF->srcipaddr);
    if (device_number != -1){
        //printf("Printing the sequence number: %d \n", device_list[device_number].sequence_number);

        hkdf_extract(salt, sizeof(salt), device_list[device_number].secret_key, sizeof(device_list[device_number].secret_key), 
        device_list[device_number].prk, sizeof(device_list[device_number].prk));
        hkdf(device_number, received_packet->timestamp);

        initialize_AES(device_list[device_number].current_key);

        printf("NEW KEY: ");
        for (int j = 0; j < 16; j++) {
            printf("%02x", device_list[device_number].current_key[j]);
        }
        printf("\n");

        uint8_t ciphertext[16+8]; 
        packet_number = received_packet->sequence_number;
        device_list[device_number].sequence_number = packet_number;
        printf("Printing the sequence number: %u \n", device_list[device_number].sequence_number);
        
        for (int i = 0; i < 24; i++) {
            ciphertext[i] = received_packet->payload[i];
        }

        iv = received_packet->partial_nonce;

        /*printf("Key for this device is: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", device_list[device_number].current_key[i]);
        }
        printf("\n");
        printf("Received Ciphertext: ");
        for (int i = 0; i < sizeof(ciphertext); i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\n");*/

        uint64_t sender_suffix = 0;
        for (int i = 0; i < 8; i++) {
            sender_suffix = (sender_suffix << 8) | sender_addr->u8[8 + i];
        }
        //printf("Sender Suffix: %llx\n", sender_suffix);

        for (int i = 0; i < 8; i++) {
            nonce[i] = (sender_suffix >> (56 - i * 8)) & 0xFF;
        }
        for (int i = 0; i < 5; i++) {
            nonce[i + 8] = (iv >> (32 - i * 8)) & 0xFF;
        }

        /*printf("Nonce: ");
        for (int i = 0; i < 13; i++) {
            printf("%02x", nonce[i]);
        }
        printf("\n");*/
        
        decrypt(device_list[device_number].current_key, 16, ciphertext, 24, device_number);
    }
}
/*---------------------------------------------------------------------------*/
int convert_char_to_hex(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return 0; // Invalid character, return default value
}
void convert_string_to_uint8(const char* hexString, uint8_t* byteArray, size_t byteArraySize) {
    int hexStringLength = strlen(hexString);
    int byteArrayLength = byteArraySize * sizeof(uint8_t);
    int minByteLength = (hexStringLength < byteArrayLength) ? hexStringLength : byteArrayLength;

    // Convert each pair of hexadecimal characters to a byte
    for (int i = 0; i < minByteLength; i += 2) {
        byteArray[i / 2] = (convert_char_to_hex(hexString[i]) << 4) | convert_char_to_hex(hexString[i + 1]);
    }
}
/*---------------------------------------------------------------------------*/
PROCESS(smart_meter_process, "Smart meter process");
AUTOSTART_PROCESSES(&smart_meter_process);
PROCESS_THREAD(smart_meter_process, ev, data)
{

    PROCESS_BEGIN();

    NETSTACK_ROUTING.root_start();

    /* Initialize BROADCAST connection */
    simple_udp_register(&broadcast_conn, 1234, NULL, 1234, broadcast_rx_callback);

    simple_udp_register(&unicast_conn, 5678, NULL, 5678, unicast_rx_callback);

    // ------------------------ Create broadcast address ------------------------
    //uip_create_linklocal_allnodes_mcast(&broadcast);

    serial_line_init();
    uart0_set_input(serial_line_input_byte);

    ccm = malloc(sizeof(struct tc_ccm_mode_struct));
    ccm->sched = malloc(sizeof(struct tc_aes_key_sched_struct));

    while(1) {
        
        //ctimer_set(&check_reponse_timer, 20 * CLOCK_SECOND, validate_addition, NULL);
        if (ev == serial_line_event_message && data != NULL) {
            // Parse the IPv6 address string
            char *token = strtok((char *)data, "/");
            uip_ipaddr_t link_local_address;
            if (uiplib_ipaddrconv(token, &link_local_address)) {
                // Get the second token
                token = strtok(NULL, "/");
                // Save the second token in secret_key of device_list[num]
                if (token != NULL) {
                    if (strlen(token) == 64){
                        convert_string_to_uint8(token, device_list[number_of_devices].secret_key, 64);
                        printf("Device %d - Secret Key: ", number_of_devices);
                        for (int i = 0; i < 32; i++) {
                            printf("%02x", device_list[number_of_devices].secret_key[i]);
                        }
                        printf("\n");
                        memcpy(&device_list[number_of_devices].link_local_address, &link_local_address, sizeof(uip_ipaddr_t));
                        printf("Device %d - Link Local Address: ", number_of_devices);
                        uiplib_ipaddr_print(&device_list[number_of_devices].link_local_address);
                        printf("\n");
                        device_list[number_of_devices].filled = true;
                        send_first_unicast(number_of_devices);
                        number_of_devices+=1;
                    } else {
                        printf("Invalid key size entered.\n");
                    }
                }            
            } else {
                printf("Invalid IPv6 address: %s\n", (char*) data);
            }
        }
        PROCESS_YIELD();
    }

    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
