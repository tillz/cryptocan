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
    struct sockaddr_can addr;
    struct ifreq ifr;

    int cipher1_id, cipher2_id;
    cipher1_id = cipher2_id = 268435456 | CAN_EFF_FLAG;
    if(plainChannel < 0) {
        fprintf(stderr, "Couldnt connect: %d\n", plainChannel);
    }
    if(cipherChannel < 0) {
        fprintf(stderr, "Couldnt connect: %d\n", cipherChannel);
    }

    // Channel where plain messages are being received
    strcpy(ifr.ifr_name, (getenv("CAN_RX") ? getenv("CAN_RX") : "can0"));
    ioctl(plainChannel, SIOCGIFINDEX, &ifr);
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    bind(plainChannel, (struct sockaddr*)&addr, sizeof(addr));

    strcpy(ifr.ifr_name, (getenv("CAN_TX") ? getenv("CAN_TX") : "can1"));
    ioctl(cipherChannel, SIOCGIFINDEX, &ifr);
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    bind(cipherChannel, (struct sockaddr*)&addr, sizeof(addr));

    // generate random key
    //     uint8_t kRaw[AES_BITS/8]={0};
    //     randombytes_buf(kRaw, AES_BITS/8);
    uint8_t kRaw[] = "NOT A REAL KEY!";

    EVP_CIPHER_CTX* context;
    context = EVP_CIPHER_CTX_new();

    struct can_frame plain;
    struct can_frame cipher_1;
    struct can_frame cipher_2;
    int recv_l;
    while(1) {
        recv_l = recv(plainChannel, &plain, sizeof(plain), 0);
        if(recv_l > 0) {

            if(getenv("VERBOSE")) {
                printFrame("Received", &plain);
            }
            char magic[] = {0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF};
            if(memcmp(plain.data, magic, 8) == 0) {
                printf("received magic!\n");
                write(cipherChannel, &plain, sizeof(struct can_frame));
                continue;
            }

            uint8_t newFrame[16];
            uint8_t newFrame_encrypted[16];
            int res;
            int reslen = 0;
            int len = 16;
            memset(newFrame, 0, 16);
            uint32_t can_id = plain.can_id & 0b00011111111111111111111111111111;
            newFrame[2] = ((plain.can_id & CAN_EFF_FLAG) == 0) ? 0 : 1;
            memcpy(newFrame + 3, &can_id, 4);
            newFrame[7] = plain.can_dlc;
            memcpy(newFrame + 8, plain.data, (plain.can_dlc > 8 ? 8 : plain.can_dlc));
            EVP_EncryptInit_ex(context, CRYPTO_CIPH(), NULL, kRaw, 0);
            EVP_CIPHER_CTX_set_padding(context, 0);
            EVP_EncryptUpdate(context, newFrame_encrypted, &reslen, newFrame, len);
            if(reslen != len) {
                printf("Failed to encrypt. Encrypted %d bytes, should be %d\n", reslen, len);
                exit(1);
            }

            // should do nothing!
            EVP_EncryptFinal_ex(context, newFrame_encrypted, &reslen);

            // cleanup
            EVP_CIPHER_CTX_cleanup(context);
            cipher_1.can_id = cipher1_id;
            cipher_2.can_id = cipher2_id;
            cipher_1.can_dlc = cipher_2.can_dlc = 8;
            memcpy(cipher_1.data, newFrame_encrypted, 8);
            memcpy(cipher_2.data, newFrame_encrypted + 8, 8);
            if(getenv("VERBOSE")) {
                printFrame("About to Send encrypted 1", &cipher_1);
            }
            if(getenv("VERBOSE")) {
                printFrame("About to Send encrypted 2", &cipher_2);
            }
            res = write(cipherChannel, &cipher_1, sizeof(struct can_frame));
            if(getenv("VERBOSE")) {
                fprintf(stderr, "write ret: %d, %d, %s\n", res, errno, strerror(errno));
            }
            res = write(cipherChannel, &cipher_2, sizeof(struct can_frame));
            if(getenv("VERBOSE")) {
                fprintf(stderr, "write ret: %d, %d, %s\n", res, errno, strerror(errno));
            }
        }
        if(getenv("VERBOSE")) {
            fprintf(stderr, "Handled 1 Frame\n");
        }
    }
}
