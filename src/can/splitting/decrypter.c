/*
Cryptocan - a minimalistic, backward-compatible, and failure resistant CAN-bus encryption
Copyright (C) 2019 Till Zimmermann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
*/
#include <errno.h>
#include <inttypes.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#define AES_BITS 128
#define CRYPTO_CIPH EVP_aes_128_ecb
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

void printFrame(char* note, struct can_frame* f) {
    fprintf(stderr, "%s: ID: %ul, Len: [%d]/[%d], %02x %02x %02x %02x %02x %02x %02x %02x\n", note, f->can_id, f->can_dlc, f->__res0, f->data[0], f->data[1], f->data[2], f->data[3], f->data[4], f->data[5], f->data[6], f->data[7]);
}
void printHex(char* what, uint8_t len) {
    for(int i = 0; i < len; i++) {
        printf("%02X ", what[i]);
    }
    printf("\n");
}

int main(int argc, char** argv) {
    int plainChannel = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    int cipherChannel = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    struct sockaddr_can addr1;
    struct sockaddr_can addr2;
    struct ifreq ifr1;
    struct ifreq ifr2;

    int cipher1_id, cipher2_id;
    cipher1_id = cipher2_id = 268435456;
    if(plainChannel < 0) {
        fprintf(stderr, "Couldnt connect: %d\n", plainChannel);
    }
    if(cipherChannel < 0) {
        fprintf(stderr, "Couldnt connect: %d\n", cipherChannel);
    }

    // Channel where encrypted messages are being received
    strcpy(ifr1.ifr_name, (getenv("CAN_RX") ? getenv("CAN_RX") : "can0"));
    ioctl(cipherChannel, SIOCGIFINDEX, &ifr1);
    addr1.can_family = AF_CAN;
    addr1.can_ifindex = ifr1.ifr_ifindex;
    bind(cipherChannel, (struct sockaddr*)&addr1, sizeof(addr1));

    strcpy(ifr2.ifr_name, (getenv("CAN_TX") ? getenv("CAN_TX") : "can1"));
    ioctl(plainChannel, SIOCGIFINDEX, &ifr2);
    addr2.can_family = AF_CAN;
    addr2.can_ifindex = ifr2.ifr_ifindex;
    bind(plainChannel, (struct sockaddr*)&addr2, sizeof(addr2));

    // generate random key
    //     uint8_t kRaw[AES_BITS/8]={0};
    //     randombytes_buf(kRaw, AES_BITS/8);
    uint8_t kRaw[] = "NOT A REAL KEY!";

    EVP_CIPHER_CTX* context;
    context = EVP_CIPHER_CTX_new();

    struct can_frame cipher;
    struct can_frame plain;
    unsigned char last[8];
    int ctr = 0;
    int recv_l;
    while(1) {
        recv_l = recv(cipherChannel, &cipher, sizeof(cipher), 0);
        if(recv_l > 0) {
            char magic[] = {0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF};
            if(memcmp(cipher.data, magic, 8) == 0) {
                write(plainChannel, &cipher, sizeof(struct can_frame));
                printf("received magic!\n");
                ctr = 0;
                continue;
            }
            unsigned char fullFrame[16];
            unsigned char fullFrame_decrypted[16];
            int readyToDecrypt = 0;
            if(getenv("VERBOSE")) {
                printFrame("Received", &cipher);
            }
            uint32_t can_id = cipher.can_id & 0b00011111111111111111111111111111;

            // Frame matching?
            if(cipher.can_dlc == 8 && (can_id == cipher1_id || can_id == cipher2_id)) {
                ctr++;
                if(ctr % 2 == 0) {
                    if(getenv("VERBOSE")) {
                        printf("Got second message, decrypting!\n");
                    }
                    memcpy(fullFrame, last, 8);
                    memcpy(fullFrame + 8, cipher.data, 8);
                    readyToDecrypt = 1;
                } else {
                    if(getenv("VERBOSE")) {
                        printf("Got first message, waiting!\n");
                    }
                    memcpy(last, cipher.data, 8);
                }
            }

            if(readyToDecrypt) {
                int res;
                int reslen = 0;
                int len = 16;
                EVP_DecryptInit_ex(context, CRYPTO_CIPH(), NULL, kRaw, 0);
                EVP_CIPHER_CTX_set_padding(context, 0);
                EVP_DecryptUpdate(context, fullFrame_decrypted, &reslen, fullFrame, len);
                if(reslen != len) {
                    printf("Failed to decrypt. Encrypted %d bytes, should be %d\n", reslen, len);
                    exit(1);
                }

                // should do nothing!
                EVP_DecryptFinal_ex(context, fullFrame_decrypted + reslen, &reslen);

                // cleanup
                EVP_CIPHER_CTX_cleanup(context);
                // clear new frame
                memset(&plain, 0, sizeof(plain));

                // copy can_id
                uint32_t can_id;
                memcpy(&can_id, fullFrame_decrypted + 3, 4);

                uint8_t eff = (fullFrame_decrypted[2] ? 1 : 0);

                // set flag & id
                plain.can_id = can_id | (eff ? CAN_EFF_FLAG : 0);
                // set len
                plain.can_dlc = fullFrame_decrypted[7];

                // secure: max 8 Bytes
                plain.can_dlc = (plain.can_dlc > 8) ? 8 : plain.can_dlc;

                // copy over data
                memcpy(plain.data, fullFrame_decrypted + 8, plain.can_dlc);

                if(getenv("VERBOSE")) {
                    printFrame("About to Send decrypted", &plain);
                }
                res = write(plainChannel, &plain, sizeof(struct can_frame));
                if(getenv("VERBOSE")) {
                    fprintf(stderr, "write ret: %d, %d, %s\n", res, errno, strerror(errno));
                }
            }
        }
        if(getenv("VERBOSE")) {
            fprintf(stderr, "Handled 1 Frame\n");
        }
    }
}