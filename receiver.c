#include "rtp.h"
#include "util.h"
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#define MAX_RETRY 50
#define MAX_PACKET_SIZE 1472

//global variables
struct sockaddr_in lstAddr;
socklen_t addr_len = sizeof(lstAddr);
int sock_fd, port, window_size, mode;
char file_path[256];
rtp_packet_t packet_send, packet_recv;
char buffer_send[MAX_PACKET_SIZE] = {0};


void build_socket(){
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock_fd <= 0){
        LOG_FATAL("Error socket_fd!");
        return;
    }
    memset(&lstAddr, 0, sizeof(lstAddr));  // dstAddr is the receiver's location in the network
    lstAddr.sin_family = AF_INET;
    lstAddr.sin_addr.s_addr = htonl(INADDR_ANY);  // receiver accepts incoming data from any address
    lstAddr.sin_port = htons(port);  // but only accepts data coming from a certain port
    bind(sock_fd, (struct sockaddr*) &lstAddr, sizeof(lstAddr));  // assign the address to the listening socket
}

void make_packet(rtp_packet_t* packet, uint32_t seq_num, uint16_t length, uint8_t flags){
    packet->rtp.seq_num = seq_num;
    packet->rtp.length = length;
    packet->rtp.checksum = 0;
    packet->rtp.flags = flags;
    if(length){
        memcpy(packet->payload, buffer_send, length);
    }
    packet->rtp.checksum = compute_checksum(packet, sizeof(rtp_header_t) + packet->rtp.length);
}

int send_packet(){
    return sendto(sock_fd, &packet_send, sizeof(rtp_header_t) + packet_send.rtp.length, 0,
                    (struct sockaddr *)&lstAddr, sizeof(lstAddr));
}

int recv_packet(){
    int recv = recvfrom(sock_fd, &packet_recv, MAX_PACKET_SIZE, MSG_DONTWAIT,
                    (struct sockaddr *)&lstAddr, &addr_len);
    if(recv <= 0 || (recv != (sizeof(rtp_header_t) + packet_recv.rtp.length))) return -1;
    return recv;
}

bool checksum(rtp_packet_t packet){
    uint32_t check_sum = packet.rtp.checksum;
    packet.rtp.checksum = 0;
    return check_sum == compute_checksum(&packet, sizeof(rtp_header_t) + packet.rtp.length);
}

double ms2s(clock_t t){
    return (double)t / CLOCKS_PER_SEC;
}

uint32_t seq_plus(uint32_t seq_num, int increment) {
    if(increment > 0){
        while(increment--){
            seq_num++;
            if(seq_num >= (1<<30)) seq_num -= (1<<30);
        }
    }
    else if(increment < 0){
        while(increment < 0){
            seq_num--;
            if((int)seq_num < 0) seq_num += (1<<30);
            increment++;
        }
    }
    return seq_num;
}

bool in_window(uint32_t seq_num, uint32_t s, int step){
    int bias = step > 0 ? 0 : 1;
    for(int i = 0; i < window_size + bias; ++i){
        if(s == seq_num) return true;
        s = seq_plus(s, step * 1);
    }
    return false;
}

uint32_t resend_packet(clock_t start, rtp_header_flag_t flags){
    int try_times = 0;
    bool received = false;
    while(try_times < MAX_RETRY){
        while(ms2s(clock() - start) < 0.1){
            if(recv_packet() <= 0 || packet_recv.rtp.length || !checksum(packet_recv) ||
                !(packet_recv.rtp.flags & flags)){ 
                continue;
            }
            else{
                received = true;
                break;
            }
        }
        if(received){
            return packet_recv.rtp.seq_num;
        }
        else{
            send_packet();
            try_times++;
            start = clock();
        }
    }
    LOG_FATAL("Not received!\n");
}

uint32_t build_connection(){
    build_socket();

    clock_t cur = clock();
    bool received = false;
    while(ms2s(clock() - cur) < 5.0){
        if(recv_packet() > 0 && !packet_recv.rtp.length && checksum(packet_recv) && packet_recv.rtp.flags == RTP_SYN){
            received = true;
            break;
        }
    }
    if(!received) LOG_FATAL("Fail to connect!\n");

    make_packet(&packet_send, seq_plus(packet_recv.rtp.seq_num, 1), 0, RTP_ACK | RTP_SYN);
    send_packet();

    if(resend_packet(clock(), RTP_ACK) < 0) LOG_FATAL("No response!\n");
    LOG_DEBUG("Connection built!\n");
    return packet_recv.rtp.seq_num;
}

uint32_t GBN(uint32_t seq_num){
    FILE *file = fopen(file_path, "wb");
    if (!file) {
        LOG_FATAL("Error: Unable to open file");
    }

    uint32_t base = seq_num;
    clock_t cur = clock();
    while(ms2s(clock() - cur) < 5.0){
        if(recv_packet() > 0 && checksum(packet_recv)){
            if(packet_recv.rtp.length == 0 || (packet_recv.rtp.flags & (RTP_ACK | RTP_SYN))){
                cur = clock();
                continue;
            }
            if(packet_recv.rtp.flags == RTP_FIN){
                LOG_DEBUG("Receiving FIN\n");
                return base;
            }
            if(packet_recv.rtp.seq_num != base){
                cur = clock();
                // LOG_DEBUG("Receiving invalid packet\n");
                continue;
            }
            fwrite(packet_recv.payload, 1, packet_recv.rtp.length, file);
            base = seq_plus(base, 1);
            // LOG_DEBUG("Cur base %d\n", base);
            make_packet(&packet_send, base, 0, RTP_ACK);
            send_packet();
            // LOG_DEBUG("Sent ACK with %d\n", base);
            cur = clock();
        }
    }
    return 1<<30;
}

uint32_t SR(uint32_t seq_num){
    FILE *file = fopen(file_path, "wb");
    if (!file) {
        LOG_FATAL("Error: Unable to open file");
    }

    uint32_t base = seq_num;
    rtp_packet_t* window = (rtp_packet_t*) malloc(sizeof(rtp_packet_t) * (window_size + 1));
    bool* acks = (bool*) malloc(sizeof(bool) * (window_size + 1));

    clock_t cur = clock();
    while(ms2s(clock() - cur) < 5.0){
        if(recv_packet() > 0 && checksum(packet_recv)){
            //收到先前的包
            if(packet_recv.rtp.length == 0 || packet_recv.rtp.flags & (RTP_ACK | RTP_SYN)){
                cur = clock();
                continue;
            }
            // LOG_DEBUG("base %d\n", base);
            // LOG_DEBUG("Receiving %d\n", packet_recv.rtp.seq_num);
            //终止标志
            if(packet_recv.rtp.flags == RTP_FIN){
                free(window);
                free(acks);
                LOG_DEBUG("Receiving FIN\n");
                return packet_recv.rtp.seq_num;
            }
            //在窗口内
            if(in_window(packet_recv.rtp.seq_num, base, 1)){
                make_packet(&packet_send, packet_recv.rtp.seq_num, 0, RTP_ACK);
                send_packet();
                //避免重复缓存
                if(acks[packet_recv.rtp.seq_num % window_size] == false){
                    //缓存收到的包
                    acks[packet_recv.rtp.seq_num % window_size] = true;
                    memcpy(buffer_send, packet_recv.payload, packet_recv.rtp.length);
                    make_packet(&window[packet_recv.rtp.seq_num % window_size], packet_recv.rtp.seq_num, packet_recv.rtp.length, packet_recv.rtp.flags);
                    //保存连续包
                    if(packet_recv.rtp.seq_num == base){
                        while(acks[base % window_size] == true){
                            fwrite(window[base % window_size].payload, 1, window[base % window_size].rtp.length, file);
                            // LOG_DEBUG("Writing %d\n", base);
                            acks[base % window_size] = false;
                            base = seq_plus(base, 1);
                        }
                    }
                }
            }
            else if(in_window(packet_recv.rtp.seq_num, base, -1)){
                make_packet(&packet_send, packet_recv.rtp.seq_num, 0, RTP_ACK);
                send_packet();
            }
            cur = clock();
        }
    }
    free(window);
    free(acks);
    return 1<<30;
}

void quit(uint32_t seq_num){
    make_packet(&packet_send, seq_num, 0, RTP_ACK | RTP_FIN);
    send_packet();

    clock_t cur = clock();
    while(ms2s(clock() - cur) < 5.0){
        if(recv_packet() > 0 && checksum(packet_recv) && packet_recv.rtp.flags == RTP_FIN){ //!packet_recv.rtp.length && 
            LOG_DEBUG("Receving FIN again\n");
            send_packet();
            cur = clock();
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 5) {
        LOG_FATAL("Usage: ./receiver [listen port] [file path] [window size] "
                  "[mode]\n");
    }

    // your code here
    port = atoi(argv[1]);
    strcpy(file_path, argv[2]);
    window_size =  atoi(argv[3]);
    mode = atoi(argv[4]);

    uint32_t seq_num = build_connection();
    if (mode == 0){
        seq_num = GBN(seq_num);
    }
    else{
        seq_num = SR(seq_num);
    }

    if(seq_num != (1<<30)) quit(seq_num);

    LOG_DEBUG("Receiver: exiting...\n");
    return 0;
}
