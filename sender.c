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
#define MAX_FILE_LEN 1461

//global variables
struct sockaddr_in dstAddr;
socklen_t addr_len = sizeof(dstAddr);
int sock_fd, receiver_port, window_size, mode;
char receiver_ip[16], file_path[256];
rtp_packet_t packet_send, packet_recv;
char buffer_send[MAX_FILE_LEN] = {0};


void build_socket(){
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock_fd <= 0){
        LOG_FATAL("Error socket_fd!");
        return;
    }
    memset(&dstAddr, 0, sizeof(dstAddr));  // dstAddr is the receiver's location in the network
    dstAddr.sin_family = AF_INET;
    inet_pton(AF_INET, receiver_ip, &dstAddr.sin_addr);
    dstAddr.sin_port = htons(receiver_port);
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
                    (struct sockaddr *)&dstAddr, sizeof(dstAddr));
}

int recv_packet(){
    int recv = recvfrom(sock_fd, &packet_recv, sizeof(packet_recv), MSG_DONTWAIT,
                    (struct sockaddr *)&dstAddr, &addr_len);
    if(recv <= 0 || recv != sizeof(rtp_header_t) + packet_recv.rtp.length) return -1;
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

    uint32_t seq_num = rand();
    // LOG_DEBUG("seq_num: %d\n", seq_num);
    make_packet(&packet_send, seq_num, 0, RTP_SYN);
    send_packet();

    if(resend_packet(clock(), RTP_SYN | RTP_ACK) < 0) LOG_FATAL("No response!\n");
    // LOG_DEBUG("received seq_num: %d\n", packet_recv.rtp.seq_num);  

    make_packet(&packet_send, packet_recv.rtp.seq_num, 0, RTP_ACK);
    send_packet();

    clock_t cur = clock();
    while(ms2s(clock() - cur) < 2){
        if(recv_packet() > 0 && (packet_recv.rtp.flags & (RTP_ACK | RTP_SYN)) && checksum(packet_recv)){
            send_packet();
            cur = clock();
        }
    }
    LOG_DEBUG("Connection built!\n");
    return packet_recv.rtp.seq_num;
}

clock_t resend_N(uint32_t base, uint32_t next_seq_num, rtp_packet_t* window){
    for(uint32_t i = base; i < next_seq_num; i = seq_plus(i, 1)){
        sendto(sock_fd, &window[i % window_size], sizeof(rtp_header_t) + window[i % window_size].rtp.length, 0, 
                (struct sockaddr*) &dstAddr, sizeof(dstAddr));
    }
    return clock();
}

uint32_t GBN(uint32_t seq_num){
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        LOG_FATAL("Error: Unable to open file");
    }

    rtp_packet_t* window = (rtp_packet_t*) malloc(sizeof(rtp_packet_t) * (window_size + 1));
    uint32_t base = seq_num, next_seq_num = seq_num;
    clock_t cur = clock(), accumulated_cur = clock();
    bool ended = false;

    while(1){
        if(ms2s(clock() - accumulated_cur) > 5.0) return 1<<30;
        while(in_window(next_seq_num, base, 1) && !ended){
            // LOG_DEBUG("%d\n", base);
            //超时重传窗口中未ACK的
            if(ms2s(clock() - cur) > 0.1){
                cur = resend_N(base, next_seq_num, window);
            }
            int len = fread(buffer_send, 1, MAX_FILE_LEN, file);
            //发送
            if(len > 0){
                make_packet(&window[next_seq_num % window_size], next_seq_num, len, 0);
                make_packet(&packet_send, next_seq_num, len, 0);
                send_packet();
                next_seq_num = seq_plus(next_seq_num, 1);
            }
            //文件读取并发送完毕
            else if(feof(file)){
                ended = true;
                break;
            }
            // 发生读取错误
            else if(ferror(file)){
                LOG_FATAL("Error occurred while reading the file.\n");
            }
            //每发送一条尝试接受一次，实时更新base
            if(recv_packet() > 0 && (packet_recv.rtp.flags & RTP_ACK) && !packet_recv.rtp.length && checksum(packet_recv)){
                if(in_window(seq_plus(packet_recv.rtp.seq_num, -1), base, 1)){
                    base = packet_recv.rtp.seq_num;
                    accumulated_cur = clock();
                    cur = clock();
                }
            }
        }
        //窗口内均发送完毕但仍未超时
        while(ms2s(clock() - cur) < 0.1){
            if(recv_packet() > 0 && (packet_recv.rtp.flags & RTP_ACK) && !packet_recv.rtp.length && checksum(packet_recv)){
                if(in_window(seq_plus(packet_recv.rtp.seq_num, -1), base, 1)){
                    base = packet_recv.rtp.seq_num;
                    accumulated_cur = clock();
                    cur = clock();
                    break;
                }
            }
        }
        //超时，则重新发送并更新cur，进入下一循环
        if(ms2s(clock() - cur) >= 0.1){
            cur = resend_N(base, next_seq_num, window);
        }
        //发送完毕
        if(base == next_seq_num && ended){
            break;
        }
    }
    free(window);
    return base;
}

clock_t resend_SR(uint32_t base, uint32_t next_seq_num, rtp_packet_t* window, bool* acks){
    for(uint32_t i = base; i < next_seq_num; i = seq_plus(i, 1)){
        if(acks[i % window_size] == false){
            sendto(sock_fd, &window[i % window_size], sizeof(rtp_header_t) + window[i % window_size].rtp.length, 0, 
                    (struct sockaddr*) &dstAddr, sizeof(dstAddr));
        }
    }
    return clock();
}

uint32_t SR(uint32_t seq_num){
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        LOG_FATAL("Error: Unable to open file");
    }

    rtp_packet_t* window = (rtp_packet_t*) malloc(sizeof(rtp_packet_t) * (window_size + 1));
    bool* acks = (bool*) malloc(sizeof(bool) * (window_size + 1));
    uint32_t base = seq_num, next_seq_num = seq_num;
    clock_t cur = clock(), accumulated_cur = clock();
    bool ended = false;

    while(1){
        // LOG_DEBUG("Begin with base %d\n", base);
        // LOG_DEBUG("Begin with next_seq_num %d\n", next_seq_num);
        if(ms2s(clock() - accumulated_cur) > 5.0) return 1<<30;
        while(in_window(next_seq_num, base, 1) && !ended){
            //超时重传窗口中未ACK的
            if(ms2s(clock() - cur) > 0.1){
                cur = resend_SR(base, next_seq_num, window, acks);
            }
            int len = fread(buffer_send, 1, MAX_FILE_LEN, file);
            //发送
            if(len > 0){
                make_packet(&window[next_seq_num % window_size], next_seq_num, len, 0);
                make_packet(&packet_send, next_seq_num, len, 0);
                send_packet();
                //设置false
                acks[next_seq_num % window_size] = false;
                // LOG_DEBUG("base %d\n", base);
                // LOG_DEBUG("sent %d\n", next_seq_num);
                next_seq_num = seq_plus(next_seq_num, 1);
            }
            //文件读取并发送完毕
            else if(feof(file)){
                ended = true;
                break;
            }
            // 发生读取错误
            else if(ferror(file)){
                LOG_FATAL("Error occurred while reading the file.\n");
            }
            //每发送一条尝试接受一次，实时更新base
            if(recv_packet() > 0 && (packet_recv.rtp.flags & RTP_ACK) && !packet_recv.rtp.length && checksum(packet_recv)){
                // LOG_DEBUG("recv %d", packet_recv.rtp.seq_num);
                //避免收到重复包
                if(in_window(packet_recv.rtp.seq_num, base, 1)){
                    //用于计算超过5秒未收到有效包
                    accumulated_cur = clock();
                    //SR ACK的为收到的seq_num
                    acks[packet_recv.rtp.seq_num % window_size] = true;
                    // LOG_DEBUG("%d true in window with base %d %d\n", packet_recv.rtp.seq_num % window_size, base % window_size, base);
                    if(packet_recv.rtp.seq_num == base){
                        //寻找第一个未被ACK的，或者全ACK从头开始
                        while(acks[base % window_size]){
                            if(base == seq_plus(packet_recv.rtp.seq_num, window_size)){
                                break;
                            }
                            base = seq_plus(base, 1);
                        }
                        // LOG_DEBUG("Updated base %d %d\n", base % window_size, base);
                        cur = clock();
                    }
                }
            }
        }
        // LOG_DEBUG("Done window\n");
        //窗口内均发送完毕但仍未超时
        while(ms2s(clock() - cur) < 0.1){
            if(recv_packet() > 0 && (packet_recv.rtp.flags & RTP_ACK)){
                if(in_window(packet_recv.rtp.seq_num, base, 1)){
                    // LOG_DEBUG("recv %d", packet_recv.rtp.seq_num);
                    //用于计算超过5秒未收到有效包
                    accumulated_cur = clock();
                    //SR ACK的为收到的seq_num
                    acks[packet_recv.rtp.seq_num % window_size] = true;
                    // LOG_DEBUG("%d true in window with base %d %d\n", packet_recv.rtp.seq_num % window_size, base % window_size, base);
                    if(packet_recv.rtp.seq_num == base){
                        //寻找第一个未被ACK的，或者全ACK从头开始
                        while(acks[base % window_size]){
                            if(base == seq_plus(packet_recv.rtp.seq_num, window_size)){
                                break;
                            }
                            base = seq_plus(base, 1);
                        }
                        // LOG_DEBUG("Updated base %d %d\n", base % window_size, base);
                        cur = clock();
                        break;
                    }
                }
            }
        }
        //超时，则重新发送并更新cur，进入下一循环
        if(ms2s(clock() - cur) >= 0.1){
            // LOG_DEBUG("Resending\n");
            cur = resend_SR(base, next_seq_num, window, acks);
        }
        if(ended) LOG_DEBUG("Ended\n");
        //发送完毕，考虑到base可能越界，如果ended而且全ACK
        if(in_window(base, next_seq_num, 1) && ended){
            break;
        }
    }
    free(window);
    free(acks);
    return next_seq_num; //base可能越界，ended的时候
}

void quit(uint32_t seq_num){
    make_packet(&packet_send, seq_num, 0, RTP_FIN);
    send_packet();
    
    if(resend_packet(clock(), RTP_FIN | RTP_ACK) < 0) LOG_FATAL("Error FIN!\n");
}

int main(int argc, char **argv) {
    if (argc != 6) {
        LOG_FATAL("Usage: ./sender [receiver ip] [receiver port] [file path] "
                  "[window size] [mode]\n");
    }

    // your code here
    strcpy(receiver_ip, argv[1]);
    receiver_port = atoi(argv[2]);
    strcpy(file_path, argv[3]);
    window_size = atoi(argv[4]);
    mode = atoi(argv[5]);

    uint32_t seq_num = build_connection();
    if(mode == 0){
        seq_num = GBN(seq_num);
        if(seq_num != (1<<30)) quit(seq_num);
    }
    else{
        seq_num = SR(seq_num);
        if(seq_num != (1<<30))quit(seq_num);
    }

    LOG_DEBUG("Sender: exiting...\n");
    return 0;
}
