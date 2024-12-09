#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <sstream>
#include <fstream>
#include <filesystem>

using namespace std;

//constant variable
#define MAX_BUF_LEN 4096
const string shell_prefix = "Client ";
const char protocol[7] = {'\xc1', '\xa1', '\x10', 'f', 't', 'p', '\0'};

//global flags
bool connected = false;

//global variable
int sockfd;
ssize_t ret = 0;
string input;
string ip = "";
string port = "";
char buf_send[MAX_BUF_LEN] = {0};
char buf_recv[MAX_BUF_LEN] = {0};
char buf_file_head_info[MAX_BUF_LEN] = {0};
char file[MAX_BUF_LEN] = {0};

//ftp
struct myFTPmessage{
    byte m_protocol[6]; /* protocol magic number (6 bytes) */
    byte m_type;                          /* type (1 byte) */
    byte m_status;                      /* status (1 byte) */
    uint32_t m_length;                    /* length (4 bytes) in Big endian*/
} __attribute__ ((packed));

//command arguments
struct Args{
    string args1;
    string args2;
}args;

//functions
int open(Args args);
int ls(Args args);
int cd(Args args);
int get(Args args);
int put(Args args);
int sha256(Args args);
int quit(Args args);

//clear buffer before send message
void clear_buffer(){
    memset(buf_send, 0, sizeof(buf_send));
    memset(buf_recv, 0, sizeof(buf_recv));
    memset(buf_file_head_info, 0, sizeof(buf_file_head_info));
    memset(file, 0, sizeof(file));
}

//python split
vector<string> split(const string &s)
{
    stringstream ssm(s);
    string strTmp;

    vector<string> result;

    while(getline(ssm, strTmp, ' '))
    {
        if(strTmp.length())
            result.push_back(strTmp);
    }
    return result;
}

//process command string
int decode_cmd(string input){
    auto cmd_args = split(input);
    // for(auto i: cmd_args){
    //     cout<<i<<endl;
    // }
    int len = cmd_args.size();
    if(len > 3 || len == 0) return -1;
    //decode
    string action = cmd_args[0];
    args.args1 = len > 1?cmd_args[1]:"";
    args.args2 = len > 2?cmd_args[2]:"";
    //switch
    // cout<<action<<endl;
    if(action=="open"){
        return open(args);
    }
    if(action=="ls"){
        return ls(args);
    }
    if(action=="cd"){
       return cd(args);
    }
    if(action=="get"){
        return get(args);
    }
    if(action=="put"){
        return put(args);
    }
    if(action=="sha256"){
        return sha256(args);
    }
    if(action=="quit"){
        return quit(args);
    }
    return -1;
}

//shell prefix
void cout_prefix(){
    cout<<shell_prefix;
    if(ip!=""){
        cout<<"("<<ip<<":"<<port<<") ";
    }
    else{
        cout<<"(None) ";
    }
    cout<<"> ";
}

//check connection status
bool check_connection(){
    if(connected == 0){
        cout<<"Not connected to the sercer yet."<<endl;
        return false;
    }
    return true;
}

//check if the protocol is right
bool check_protocol(const char* s){
    return s[0]=='\xc1' && s[1]=='\xa1' && s[2]=='\x10' && s[3]=='f' && s[4]=='t' && s[5]=='p';
}

//identify file type
bool isAsciiFile(){
    for(unsigned char i: file){
        if(i > 127){
            return false;
        }
    }
    return true;
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

//open
int open(Args args){
    //exceptions
    if(connected == 1){
        cout<<"You have already built a connection!"<<endl;
        return 0;
    }
    if(args.args1 == "" || args.args2 == ""){
        cout<<"Missing arguments!"<<endl;
        return -1;
    }
    ip = args.args1;
    port = args.args2;
    // cout<<ip<<port<<endl;
    //set socket fd
    struct sockaddr_in server_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0){
        cout<<"Error with socket fd!"<<endl;
        return -1;
    }
    //set server address
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);
    server_addr.sin_port = htons(atoi(port.c_str()));
    //build connection
    ret = connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if(ret < 0){
        cout<<"Error connecting!"<<endl;
        return -1;
    }
    //construct message
    myFTPmessage OPEN_CONN_REQUEST = c_request(0xA1);
    //send message
    clear_buffer();
    memcpy(buf_send, &OPEN_CONN_REQUEST, sizeof(OPEN_CONN_REQUEST));
    ret = send(sockfd, buf_send, sizeof(OPEN_CONN_REQUEST), 0);
    if(ret < 0){
        cout<<"Error sending message!"<<endl;
        return -1;
    }
    //receive message
    ret = recv(sockfd, buf_recv, sizeof(OPEN_CONN_REQUEST), 0);
    if(ret < 0){
        cout<<"Error receiving message!"<<endl;
        return -1;
    }
    myFTPmessage* recv_message = (myFTPmessage*) buf_recv;
    if(!check_protocol((char*) recv_message->m_protocol) || recv_message->m_type!=(byte)0xA2){
        cout<<"Protocol or Type error!"<<endl;
        return -1;
    }
    if(recv_message->m_status!=(byte)1){
        cout<<"Connection rejected!"<<endl;
        return -1;
    }
    cout<<"Connection successfully built!"<<endl;
    connected = 1;
    return 0;
}

int ls(Args args){
    //exceptions
    if(args.args1!="" || args.args2!=""){
        cout<<"Too many arguments!"<<endl;
        return -1;
    }
    if(!check_connection){
        return -1;
    }
    //construct message
    myFTPmessage LIST_REQUEST = c_request(0xA3);
    //send message
    clear_buffer();
    memcpy(buf_send, &LIST_REQUEST, sizeof(LIST_REQUEST));
    ret = send(sockfd, buf_send, sizeof(LIST_REQUEST), 0);
    if(ret < 0){
        cout<<"Error sending list request!"<<endl;
        return -1;
    }
    ret = recv(sockfd, buf_recv, sizeof(myFTPmessage), 0);
    if(ret < 0){
        cout<<"Error receiving message!"<<endl;
        return -1;
    }
    myFTPmessage* LIST_REPLY = (myFTPmessage*) buf_recv;
    if(!check_protocol((char*) LIST_REPLY->m_protocol) || LIST_REPLY->m_type!=(byte)0xA4){
        cout<<"Protocol or Type error!"<<endl;
        return -1;
    }
    int len = ntohl(LIST_REPLY->m_length) - 12;
    int read = 0, received = 0;
    while(read < len){
        received = recv(sockfd, file + read, MAX_BUF_LEN, 0);
        if(received == 0)continue;
        if(received < 0){
            cout<<"Error receiving file names!"<<endl;
            return -1;
        }
        read += received;
    }
    cout<<"-----------------------------------------"<<endl;
    cout<<file;
    cout<<"-----------------------------------------"<<endl;
    return 0;
}

int cd(Args args){
    if(args.args2!=""){
        cout<<"Too many arguments!"<<endl;
        return -1;
    }
    if(args.args1==""){
        cout<<"Missing arguments!"<<endl;
        return -1;
    }
    if(!check_connection){
        return -1;
    }
    myFTPmessage CHANGE_DIR_REQUEST = c_request(0xA5);
    const char* dir = args.args1.c_str();
    CHANGE_DIR_REQUEST.m_length = htonl(12 + strlen(dir) + 1);
    //send message
    clear_buffer();
    memcpy(buf_send, &CHANGE_DIR_REQUEST, sizeof(CHANGE_DIR_REQUEST));
    memcpy(buf_send + sizeof(CHANGE_DIR_REQUEST), dir, strlen(dir) + 1);
    ret = send(sockfd, buf_send, 12 + strlen(dir) + 1, 0);
    if(ret < 0){
        cout<<"Error sending cd request!"<<endl;
        return -1;
    }
    ret = recv(sockfd, buf_recv, sizeof(CHANGE_DIR_REQUEST), 0);
    if(ret < 0){
        cout<<"Error receiving message!"<<endl;
        return -1;
    } 
    myFTPmessage* CHANGE_DIR_REPLY = (myFTPmessage*) buf_recv;
    if(!check_protocol((char*) CHANGE_DIR_REPLY->m_protocol) || CHANGE_DIR_REPLY->m_type!=(byte)0xA6){
        cout<<"Protocol or Type error!"<<endl;
        return -1;
    }
    if(CHANGE_DIR_REPLY->m_status == (byte)1){
        cout<<"Changed to "<<dir<<" successfully!"<<endl;
    }
    else{
        cout<<dir<<" does not exist! Please check."<<endl;
    }
    return 0;
}

int get(Args args){
    if(args.args2!=""){
        cout<<"Too many arguments!"<<endl;
        return -1;
    }
    if(args.args1==""){
        cout<<"Missing arguments!"<<endl;
        return -1;
    }
    if(!check_connection){
        return -1;
    }
    myFTPmessage GET_REQUEST = c_request(0xA7);
    const char* file_name = args.args1.c_str();
    GET_REQUEST.m_length = htonl(12 + strlen(file_name) + 1);
    //send message
    clear_buffer();
    memcpy(buf_send, &GET_REQUEST, sizeof(GET_REQUEST));
    memcpy(buf_send + sizeof(GET_REQUEST), file_name, strlen(file_name) + 1);
    ret = send(sockfd, buf_send, 12 + strlen(file_name) + 1, 0);
    if(ret < 0){
        cout<<"Error sending cd request!"<<endl;
        return -1;
    }
    ret = recv(sockfd, buf_recv, sizeof(GET_REQUEST), 0);
    if(ret < 0){
        cout<<"Error receiving message!"<<endl;
        return -1;
    } 
    myFTPmessage* recv_message = (myFTPmessage*) buf_recv;
    if(!check_protocol((char*) recv_message->m_protocol) || recv_message->m_type!=(byte)0xA8){
        cout<<"Protocol or Type error!"<<endl;
        return -1;
    }
    if(recv_message->m_status == (byte)0){
        cout<<"File does not exist!"<<endl;
        return -1;
    }
    //first discriminate file head info
    int head_info_size = sizeof(myFTPmessage);
    int read = 0, received = 0;
    while(read < head_info_size){
        read += recv(sockfd, buf_file_head_info + read, head_info_size - read, 0);
    }
    myFTPmessage* file_head_info = (myFTPmessage*) buf_file_head_info;
    if(!check_protocol((char*) file_head_info->m_protocol) || file_head_info->m_type!=(byte)0xFF){
        cout<<"Protocol or Type error!"<<endl;
        return -1;
    }
    uint32_t file_len = ntohl(file_head_info->m_length) - 12;
    //second, read and write file 
    ofstream out(file_name, ios::out|ios::binary);
    read = 0;
    while(read < file_len){
        received = recv(sockfd, file, MAX_BUF_LEN, 0);
        if(received == 0){
            continue;
        }
        if(received < 0){
            cout<<"Error!"<<endl;
            out.close();
            return -1;
        }
        out.write(file, received);
        read += received;
    }
    // 检查是否完全接收到文件
    if (read != file_len) {
        cout << "File transfer incomplete! Received " << read << " bytes, expected " << file_len << " bytes." << endl;
        out.close();
        return -1;
    }
    bool ascii = isAsciiFile();
    out.close();// 完成写入，关闭文件
    cout<<"Successfully received "<<file_name<<endl;
    return 0;
}

int put(Args args){
    if(args.args2!=""){
        cout<<"Too many arguments!"<<endl;
        return -1;
    }
    if(args.args1==""){
        cout<<"Missing arguments!"<<endl;
        return -1;
    }
    if(!check_connection){
        return -1;
    }
    const char* file_name = args.args1.c_str();
    ifstream File(file_name, ios::binary);
    if(!File.good()){
        cout<<file_name<<" does not exist!"<<endl;
        return -1;
    }
    else{
        myFTPmessage PUT_REQUEST = c_request(0xA9);
        //获取文件大小
        uint32_t file_len = 0;
        File.seekg(0, File.end);// 移动到文件末尾
        file_len = File.tellg();
        File.seekg(0, File.beg);
        //发送put请求
        PUT_REQUEST.m_length = htonl(12 + strlen(file_name) + 1);
        clear_buffer();
        memcpy(buf_send, &PUT_REQUEST, sizeof(PUT_REQUEST));
        memcpy(buf_send + sizeof(PUT_REQUEST), file_name, strlen(file_name));
        ret = send(sockfd, buf_send, 12 + strlen(file_name) + 1, 0);
        if(ret < 0){
            cout<<"Error sending put request!"<<endl;
            return -1;
        }
        //接收put回复
        ret = recv(sockfd, buf_recv, sizeof(myFTPmessage), 0);
        if(ret < 0){
            cout<<"Error receiving message!"<<endl;
            return -1;
        }
        myFTPmessage* PUT_REPLY = (myFTPmessage*) buf_recv;
        if(!check_protocol((char*) PUT_REPLY->m_protocol) || PUT_REPLY->m_type!=(byte)0xAA){
            cout<<"Protocol or Type error!"<<endl;
            return -1;
        }
        //if(PUT_REPLY->m_status!=(byte)1){
        //    cout<<"Permission denied!"<<endl;
        //    return -1;
        //}
        //发送文件信息
        myFTPmessage file_head_info = c_request(0xFF);
        file_head_info.m_length = htonl(12 + file_len);
        memcpy(buf_file_head_info, &file_head_info, sizeof(file_head_info));
        send(sockfd, buf_file_head_info, sizeof(file_head_info), 0);
        //分段发送文件
        streamsize bytes_read;
        int sent = 0;
        while (true) {
            // 读取文件
            File.read(file, MAX_BUF_LEN);
            bytes_read = File.gcount();  // 获取读取的字节数
            // 如果读取的字节数为0，说明文件已经读取完毕
            if (bytes_read == 0) {
                break;
            }
            // 发送数据
            sent = 0;
            while(sent < bytes_read){
                ret = send(sockfd, file + sent, bytes_read - sent, 0);
                if (ret < 0) {
                    cout << "Error sending file data!" << endl;
                    File.close();  // 发送出错，关闭文件
                    return -1;
                }
                if (ret == 0) continue;
                sent += ret;
            }
        }
        File.close();// 关闭文件
        return 0;
    }
}

int sha256(Args args){
    if(args.args2!=""){
        cout<<"Too many arguments!"<<endl;
        return -1;
    }
    if(args.args1==""){
        cout<<"Missing arguments!"<<endl;
        return -1;
    }
    if(!check_connection){
        return -1;
    }
    const char* file_name = args.args1.c_str();
    clear_buffer();
    myFTPmessage SHA_REQUEST = c_request(0xAB);
    SHA_REQUEST.m_length = htonl(12 + strlen(file_name) + 1);
    memcpy(buf_send, &SHA_REQUEST, sizeof(SHA_REQUEST));
    memcpy(buf_send + sizeof(SHA_REQUEST), file_name, strlen(file_name));
    ret = send(sockfd, buf_send, 12 + strlen(file_name) + 1, 0);
    if(ret < 0){
        cout<<"Error sending sha256 request!"<<endl;
        return -1;
    }
    ret = recv(sockfd, buf_recv, sizeof(myFTPmessage), 0);
    if(ret < 0){
        cout<<"Error receiving message!"<<endl;
        return -1;
    }
    myFTPmessage* SHA_REPLY = (myFTPmessage*) buf_recv;
    if(!check_protocol((char*) SHA_REPLY->m_protocol) || SHA_REPLY->m_type!=(byte)0xAC){
        cout<<"Protocol or Type error!"<<endl;
        return -1;
    }
    if(SHA_REPLY->m_status == (byte)0){
        cout<<"File does not exist!"<<endl;
        return -1;
    }
    else{
        //first receive file head info
        int head_info_size = sizeof(myFTPmessage);
        int read = 0, received = 0;
        while(read < head_info_size){
            read += recv(sockfd, buf_file_head_info + read, head_info_size - read, 0);
        }
        myFTPmessage* file_head_info = (myFTPmessage*) buf_file_head_info;
        if(!check_protocol((char*) file_head_info->m_protocol) || file_head_info->m_type!=(byte)0xFF){
            cout<<"Protocol or Type error!"<<endl;
            return -1;
        }
        int file_len = ntohl(file_head_info->m_length) - 12;
        // cout<<file_len<<endl;
        //second, read and write file 
        read = 0;
        while(read < file_len){
            received = recv(sockfd, file + read, file_len, 0);
            if(received == 0){
                continue;
            }
            if(received < 0){
                cout<<"Error!"<<endl;
                return -1;
            }
            read += received;
        }
        cout<<"sha256 of "<<file_name<<" is: "<<endl;
        cout<<file<<endl;
        return 0;
    }
}

int quit(Args args){
    if(args.args1!=""||args.args2!=""){
        cout<<"Too many parameters!"<<endl;
        return -1;
    }
    if(!check_connection){
        return -1;
    }
    myFTPmessage QUIT_REQUEST = c_request(0xAD);
    clear_buffer();
    memcpy(buf_send, &QUIT_REQUEST, sizeof(QUIT_REQUEST));
    ret = send(sockfd, buf_send, sizeof(QUIT_REQUEST), 0);
    if(ret < 0){
        cout<<"Error sending quit request!"<<endl;
        return -1;
    }
    ret = recv(sockfd, buf_recv, sizeof(myFTPmessage), 0);
    if(ret < 0){
        cout<<"Error receiving message!"<<endl;
        return -1;
    }
    myFTPmessage* QUIT_REPLY = (myFTPmessage*) buf_recv;
    if(!check_protocol((char*) QUIT_REPLY->m_protocol) || QUIT_REPLY->m_type!=(byte)0xAE){
        cout<<"Protocol or Type error!"<<endl;
        return -1;
    }
    close(sockfd);
    connected = 0;
    ip = "";
    port = "";
    return 0;
}


int main(int argc, char** argv) {
    while(1){
        cout_prefix();
        getline(cin, input);
        // cout<<input<<endl;
        if(decode_cmd(input) < 0){
            cout<<"Please check your command or internet status!"<<endl;
        }
    }
    return 0;
}