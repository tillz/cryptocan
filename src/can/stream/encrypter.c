#include <errno.h>
#include <inttypes.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

void printFrame(char* note, struct can_frame* f) {
    fprintf(stderr, "%s: ID: %ul, Len: [%d]/[%d], %02x %02x %02x %02x %02x %02x %02x %02x\n", note, f->can_id, f->can_dlc, f->__res0, f->data[0], f->data[1], f->data[2], f->data[3], f->data[4], f->data[5], f->data[6], f->data[7]);
}

int main(int argc, char** argv) {
    int sendNonce = 0;
    uint32_t pctr = 0;
    if(sodium_init() < 0) {
        fprintf(stderr, "Sodium Init failed!\n");
        return 1;
    }
    int plainChannel = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    int cipherChannel = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    struct sockaddr_can addr;
    struct ifreq ifr;

    if(argc > 1) {
        sendNonce = atoi(argv[1]);
    }

    if(plainChannel < 0) {
        fprintf(stderr, "Couldnt connect: %d\n", plainChannel);
    }
    if(cipherChannel < 0) {
        fprintf(stderr, "Couldnt connect: %d\n", cipherChannel);
    }
    strcpy(ifr.ifr_name, "can1");
    ioctl(plainChannel, SIOCGIFINDEX, &ifr);
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    bind(plainChannel, (struct sockaddr*)&addr, sizeof(addr));

    strcpy(ifr.ifr_name, "can0");
    ioctl(cipherChannel, SIOCGIFINDEX, &ifr);
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    bind(cipherChannel, (struct sockaddr*)&addr, sizeof(addr));

    // convert key
    // ATTENTION! INSECURE KEY
    char key_bytes[] = {0x3e, 0x55, 0x95, 0xa9, 0xe7, 0xb7, 0x64, 0xb9, 0x29, 0x85, 0xea, 0xff, 0x8a, 0x44, 0x8c, 0x0e, 0x3e, 0x55, 0x95, 0xa9, 0xe7, 0xb7, 0x64, 0xb9, 0x29, 0x85, 0xea, 0xff, 0x8a, 0x44, 0x8c, 0x0e};
    //     char nonce[crypto_stream_chacha20_NONCEBYTES]={0};
    char nonce[] = {0x3e, 0x55, 0x95, 0xa9, 0xe7, 0xb7, 0x64, 0xb9, 0x29, 0x85, 0xea, 0xff, 0x8a, 0x44, 0x8c, 0x0e, 0x3e, 0x55, 0x95, 0xa9, 0xe7, 0xb7, 0x64, 0xb9, 0x29, 0x85, 0xea, 0xff, 0x8a, 0x44, 0x8c, 0x0e};

    if(sendNonce) {
        randombytes_buf(nonce, 8);
    }
    // Wir koennen die Nonce noch nicht rueberschicken. Daher (Testweise!)
    // als fest annehmen!
    nonce[crypto_stream_chacha20_NONCEBYTES - 1] = 1;
    uint64_t ctr = 0;

    struct can_frame plain;
    struct can_frame cipher;
    int recv_l;
    while(1) {
        memset(cipher.data, 0, 8);
        if(sendNonce && pctr && pctr % sendNonce == 0) {
            pctr++;
            ctr = 0;
            cipher.can_dlc = 8;
            cipher.can_id = 1 | CAN_EFF_FLAG;
            randombytes_buf(nonce, 8);
            memcpy(cipher.data, nonce, 8);
            int res = write(cipherChannel, &cipher, sizeof(struct can_frame));
            if(res > 0) {
                printFrame("Succ sent new nonce:\n", &cipher);
            } else {
                fprintf(stderr, "Failed to send new nonce!\n");
            }
        }
        recv_l = recv(plainChannel, &plain, sizeof(plain), 0);
        char magic[] = {0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF};
        if(memcmp(plain.data, magic, 8) == 0) {
            write(cipherChannel, &plain, sizeof(struct can_frame));
            pctr = ctr = 0;
            continue;
        }
        if(recv_l > 0) {
            uint32_t can_id = plain.can_id & 0b00011111111111111111111111111111;
            if(can_id != 12342) {
                fprintf(stderr, "Ignored packet on wrong id\n");
            } else {
                printFrame("Received plain frame:", &plain);
                if(plain.can_dlc > 0) {
                    crypto_stream_chacha20_xor_ic(cipher.data, plain.data, plain.can_dlc, nonce, ctr, key_bytes);
                    ctr += plain.can_dlc;
                    cipher.can_dlc = plain.can_dlc;
                } else {
                    cipher.can_dlc = 0;
                }
                cipher.can_id = plain.can_id;
                printFrame("Encrypted frame to send:", &cipher);
                int res = write(cipherChannel, &cipher, sizeof(struct can_frame));
            }
            pctr++;
        }
        fprintf(stderr, "---\n");
    }
}
