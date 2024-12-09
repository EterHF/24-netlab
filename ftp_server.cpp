#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <filesystem>
#include <unordered_map>
#include <fstream>

using namespace std;

//constant variable
#define MAX_BUF_LEN 4096
#define MAX_CLIENT_NUM 20
const char protocol[7] = {'\xc1', '\xa1', '\x10', 'f', 't', 'p', '\0'};

//global variable
string ip_address = "127.0.0.1";
int port = 12323;
int listenfd;
int client_fds[MAX_CLIENT_NUM];// = {-1}; //memset才是0和-1
pthread_t client_threads[MAX_CLIENT_NUM];
unordered_map<int, string> client_working_dir;

//ftp
struct myFTPmessage{
    byte m_protocol[6]; /* protocol magic number (6 bytes) */
    byte m_type;                          /* type (1 byte) */
    byte m_status;                      /* status (1 byte) */
    uint32_t m_length;                    /* length (4 bytes) in Big endian*/
} __attribute__ ((packed));

//clear buffer before send message
void clear_buffer(char* buf_send, char* buf_recv, char* buf_file_head_info, char* file){
    memset(buf_send, 0, sizeof(buf_send));
    memset(buf_recv, 0, sizeof(buf_recv));
    memset(buf_file_head_info, 0, sizeof(buf_file_head_info));
    memset(file, 0, sizeof(file));
}

//check if the protocol is right
bool check_protocol(const char* s){
    return s[0]=='\xc1' && s[1]=='\xa1' && s[2]=='\x10' && s[3]=='f' && s[4]=='t' && s[5]=='p';
}

//construct a request message
myFTPmessage c_request(int request_id){
    myFTPmessage REQUEST;
    for(int i = 0;i < 6; ++i){
        REQUEST.m_protocol[i] = (byte)protocol[i];
    }
    REQUEST.m_type = (byte)request_id;
    REQUEST.m_status = (byte)0;
    REQUEST.m_length = htonl(12);
    return REQUEST;
}

//for each client
void* each(void *args){
    int* connfd_ptr = (int*) args;
    int connfd = *connfd_ptr;
    // cout<<connfd<<endl;
    int ret = 0;
    char* buf_recv = new char[MAX_BUF_LEN]{0};
    char* buf_send = new char[MAX_BUF_LEN]{0};
    char* buf_file_head_info = new char[MAX_BUF_LEN]{0};
    char* file = new char[MAX_BUF_LEN]{0};
    while(1){
        clear_buffer(buf_recv, buf_send, buf_file_head_info, file);
        recv(connfd, buf_recv, sizeof(myFTPmessage), 0);
        myFTPmessage* recv_message = (myFTPmessage*) buf_recv;
        if(check_protocol((char*)recv_message->m_protocol)){
            int action = (int)recv_message->m_type;
            switch(action){
                case 0xA1:{
                    myFTPmessage OPEN_REPLY = c_request(0xA2);
                    OPEN_REPLY.m_status = (byte)1;
                    memcpy(buf_send, &OPEN_REPLY, sizeof(myFTPmessage));
                    send(connfd, buf_send, sizeof(myFTPmessage), 0);
                    client_working_dir[connfd] = filesystem::current_path().string();
                    break;
                }
                case 0xA3:{
                    myFTPmessage LIST_REPLY = c_request(0xA4);
                    int ls_len = 0, read = sizeof(LIST_REPLY), cur = 0;
                    //根据虚拟工作目录构建命令
                    string ls_cmd = "ls " + client_working_dir[connfd];
                    // cout<<ls_cmd<<endl;
                    FILE* fp = NULL;
                    fp = popen(ls_cmd.c_str(), "r");
                    if(fp){
                        while(1){
                            cur = fread(buf_send + read, 1, MAX_BUF_LEN - read - 1, fp);
                            if(cur == 0)break;
                            ls_len += cur;
                            read += cur;
                        }
                        pclose(fp);
                    }
                    LIST_REPLY.m_length = htonl(read + 1);     
                    memcpy(buf_send, &LIST_REPLY, sizeof(LIST_REPLY));
                    send(connfd, buf_send, sizeof(LIST_REPLY) + ls_len + 1, 0);
                    break;
                }
                case 0xA5:{
                    myFTPmessage* CHANGE_DIR_REQUEST = (myFTPmessage*) buf_recv;
                    myFTPmessage CHANGE_DIR_REPLY = c_request(0xA6);
                    recv(connfd, buf_recv + sizeof(myFTPmessage), ntohl(CHANGE_DIR_REQUEST->m_length) - 12, 0);
                    string dir = buf_recv + sizeof(myFTPmessage);
                    // cout<<dir<<endl;
                    //使用虚拟路径，每个客户端维护一个当前工作路径
                    string current_dir = client_working_dir[connfd];
                    filesystem::path target_dir = filesystem::path(current_dir) / filesystem::path(dir);
                    // cout<<target_dir.string()<<endl;
                    if(filesystem::exists(target_dir) && filesystem::is_directory(target_dir)){
                        client_working_dir[connfd] = target_dir.string();
                        // cout<< client_working_dir[connfd]<<endl;
                        CHANGE_DIR_REPLY.m_status = (byte)1;
                    }
                    else{
                        CHANGE_DIR_REPLY.m_status = (byte)0;
                    }
                    send(connfd, &CHANGE_DIR_REPLY, sizeof(CHANGE_DIR_REPLY), 0);
                    break;
                }
                case 0xA7:{
                    myFTPmessage* GET_REQUEST = (myFTPmessage*) buf_recv;
                    myFTPmessage GET_REPLY = c_request(0xA8);
                    //接收文件名
                    recv(connfd, buf_recv + sizeof(myFTPmessage), ntohl(GET_REQUEST->m_length) - 12, 0);
                    string file_name = buf_recv + sizeof(myFTPmessage);
                    //确定绝对路径
                    string current_dir = client_working_dir[connfd];
                    filesystem::path target_dir = filesystem::path(current_dir) / file_name;
                    string target_file = target_dir.string();
                    ifstream fp(target_file);
                    if(fp.good()){
                        fp.close();
                        GET_REPLY.m_status = (byte)1;
                        send(connfd, &GET_REPLY, sizeof(GET_REPLY), 0);
                        //获取文件大小
                        ifstream File(target_file, ios::binary);
                        uint32_t file_len = 0;
                        File.seekg(0, std::ios::end);// 移动到文件末尾
                        file_len = File.tellg();
                        File.seekg(0, std::ios::beg);
                        //发送文件信息
                        myFTPmessage file_head_info = c_request(0xFF);
                        file_head_info.m_length = htonl(12 + file_len);
                        memcpy(buf_file_head_info, &file_head_info, sizeof(file_head_info));
                        send(connfd, buf_file_head_info, sizeof(file_head_info), 0);
                        //分段发送文件
                        streamsize bytes_read;
                        while (!File.eof()) {
                            File.read(file, MAX_BUF_LEN);// 读取文件块
                            bytes_read = File.gcount();// 获取读取到的字节数
                            if (bytes_read > 0) {
                                ret = send(connfd, file, bytes_read, 0);// 发送读取到的字节
                                if (ret < 0) {
                                    cout << "Error sending file data!" << endl;
                                    File.close();
                                }
                            }
                        }
                        File.close();// 关闭文件
                    }
                    break;
                }
                case 0xA9:{
                    //接收文件名
                    myFTPmessage* PUT_REQUEST = (myFTPmessage*) buf_recv;
                    recv(connfd, buf_recv + sizeof(myFTPmessage), ntohl(PUT_REQUEST->m_length) - 12, 0);
                    string file_name = buf_recv + sizeof(myFTPmessage);
                    //发送回复
                    myFTPmessage PUT_REPLY = c_request(0xAA);
                    send(connfd, &PUT_REPLY, sizeof(PUT_REPLY), 0);
                    //接收文件信息
                    recv(connfd, buf_file_head_info, sizeof(myFTPmessage), 0);
                    myFTPmessage* file_head_info = (myFTPmessage*) buf_file_head_info;
                    uint32_t file_len = ntohl(file_head_info->m_length) - 12;
                    //接收文件
                    string current_dir = client_working_dir[connfd];
                    filesystem::path target_dir = filesystem::path(current_dir) / file_name;
                    string target_file = target_dir.string();
                    ofstream out(target_file, ios::out|ios::binary);
                    int read = 0, received = 0;
                    while(read < file_len){
                        received = recv(connfd, file, MAX_BUF_LEN, 0);
                        if(received == 0){
                            continue;
                        }
                        if(received < 0){
                            cout<<"Error!"<<endl;
                            out.close();
                        }
                        out.write(file, received);
                        read += received;
                    }
                    out.close();
                    break;
                }
                case 0xAB:{
                    //接收文件名
                    myFTPmessage* SHA_REQUEST = (myFTPmessage*) buf_recv;
                    recv(connfd, buf_recv + sizeof(myFTPmessage), ntohl(SHA_REQUEST->m_length) - 12, 0);
                    string file_name = buf_recv + sizeof(myFTPmessage);
                    //确认路径
                    string current_dir = client_working_dir[connfd];
                    filesystem::path target_dir = filesystem::path(current_dir) / file_name;
                    string target_file = target_dir.string();
                    // cout<<target_file<<endl;
                    myFTPmessage SHA_REPLY = c_request(0xAC);
                    if(filesystem::is_regular_file(target_dir)){
                        SHA_REPLY.m_status = (byte)1;
                        send(connfd, &SHA_REPLY, sizeof(SHA_REPLY), 0);
                        SHA_REPLY = c_request(0xFF);
                        //获取sha256结果
                        string sha_cmd = "sha256sum " + target_file;
                        FILE* fp = NULL;
                        fp = popen(sha_cmd.c_str(), "r");
                        int read = sizeof(SHA_REPLY), cur = 0, sha_len = 0;
                        if(fp){
                            while(1){
                                cur = fread(buf_send + read, 1, sizeof(buf_send) - read - 1, fp);
                                if(cur == 0)break;
                                sha_len += cur;
                                read += cur;
                            }
                            pclose(fp);
                            // cout<<sha_len<<endl;
                            // cout<<read<<endl;    
                            SHA_REPLY.m_length = ntohl(read + 1); 
                            memcpy(buf_send, &SHA_REPLY, sizeof(SHA_REPLY));
                            send(connfd, buf_send, read + 1, 0);
                        }
                    }
                    else{
                        SHA_REPLY.m_status = (byte)0;
                        send(connfd, &SHA_REPLY, sizeof(SHA_REPLY), 0);
                    }
                    break;
                }
                case 0xAD:{
                    myFTPmessage QUIT_REPLY = c_request(0xAE);
                    memcpy(buf_send, &QUIT_REPLY, sizeof(QUIT_REPLY));
                    send(connfd, buf_send, sizeof(QUIT_REPLY), 0);
                    close(connfd);
                    *connfd_ptr = -1;
                    delete[] buf_send;
                    delete[] buf_recv;
                    delete[] buf_file_head_info;
                    delete[] file;
                    pthread_exit(NULL);
                    break;
                }
                default:
                    break;
            } 
        }
    }
    return NULL;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        cout<<"Missing ip or port number!"<<endl;
        return 0;
    }
    string ip_address = argv[1];
    int port = atoi(argv[2]);
    // cout<<ip_address<<":"<<port<<endl;
    //set listen fd
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if(listenfd < 0){
        cout<<"Error with listen fd!"<<endl;
        return 0;
    }
    //set server address
    struct sockaddr_in client_addr, server_addr;
    socklen_t clilen = sizeof(client_addr);
    // bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip_address.c_str(), &server_addr.sin_addr);
    server_addr.sin_port = htons(port);
    //bind
    bind(listenfd, (struct sockaddr*) &server_addr, sizeof(server_addr));
    //listen
    listen(listenfd, 16);
    for(int i = 0; i < MAX_CLIENT_NUM; ++i)
        client_fds[i] = -1;
    while(1){
        int client = accept(listenfd, (struct sockaddr*) &client_addr, &clilen);
        while(client < 0){
            client = accept(listenfd, (struct sockaddr*) &client_addr, &clilen);
        }
        int new_client = -1;
        for(int i = 0; i < MAX_CLIENT_NUM; ++i){
            if(client_fds[i] == -1){
                client_fds[i] = client;
                new_client = i;
                break;
            }
        }
        if(new_client == -1){
            cout<<"Reaching max client num!"<<endl;
            continue;
        }
        pthread_create(&client_threads[new_client], NULL, each, (void *) &client_fds[new_client]);
        pthread_detach(client_threads[new_client]);
    }
    return 0;
}