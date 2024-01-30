#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8090

using namespace std;

void server(int repeat) {
    
    //同一台电脑测试，需要两个端口
    int sockfd;

    // 创建socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(-1==sockfd){
        return;
        puts("Failed to create socket");
    }

    // 设置地址与端口
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;       // Use IPV4
    addr.sin_port = htons(SERVER_PORT);    //
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Time out
    // struct timeval tv;
    // tv.tv_sec  = 0;
    // tv.tv_usec = 200000;  // 200 ms
    // setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(struct timeval));

    // Bind 端口，用来接受之前设定的地址与端口发来的信息,作为接受一方必须bind端口，并且端口号与发送方一致
    if (bind(sockfd, (struct sockaddr*)&addr, addr_len) == -1){
        printf("Failed to bind socket on port %d\n", SERVER_PORT);
        close(sockfd);
        return ;
    }
    listen(sockfd, 1024);

    struct sockaddr_in clientAddr;
    socklen_t clientAddr_len = sizeof(clientAddr);
    memset(&clientAddr, 0, sizeof(clientAddr));

    char buffer[6] = "hello";
    int counter = 0;
    while(counter < repeat){
        int conn_fd = accept(sockfd, (struct sockaddr *)&clientAddr, &clientAddr_len);

     // 阻塞住接受消息
        recv(conn_fd, buffer, 6, 0);
        buffer[6] = 0;
        printf("\rGet Message %d: %s", counter++, buffer);
        send(conn_fd, buffer, 6, 0);

        close(conn_fd);
    }

    close(sockfd);
}

void client(int repeat) {
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

    struct sockaddr_in clientAddr;
    socklen_t serverAddr_len = sizeof(serverAddr);

    double hs_time_count = 0;
    double me_time_count = 0;
    clock_t hs_tc_start, hs_tc_end;
    clock_t me_tc_start, me_tc_end;

    char buffer[1024]; 
    int len = sprintf(buffer, "Client Hello");
    int msg_total = len*repeat;

    int counter = 0;
    while(counter < repeat){
        int sockfd;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if(-1==sockfd){
            return;
            puts("Failed to create socket");
        }

        hs_tc_start = clock();
        connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
        hs_tc_end = clock();
        hs_time_count += hs_tc_end-hs_tc_start;

        me_tc_start = clock();
        send(sockfd, buffer, len, 0);
        me_tc_end = clock();
        recv(sockfd, buffer, 6, 0);
        me_time_count += me_tc_end-me_tc_start;

        buffer[6] = 0;
        // printf("\rGet Message %d: %s", counter++, buffer);
        counter++;
        close(sockfd);
    }
    
    hs_time_count = hs_time_count *1000 /CLOCKS_PER_SEC;
    me_time_count = me_time_count *1000 /(CLOCKS_PER_SEC * msg_total);
    printf("time cost:\nhandshake: %f\tmsg send: %f\n", hs_time_count, me_time_count);
}

int main(int argc, char* argv[]) {
    clock_t start, end;
    start = clock();

    int rank = 0;
    if (argc > 1 && argv[1][0] == '1') {
        rank = 1;
    }
    int repeat = 1;
    if (argc > 2) {
        repeat = atoi(argv[2]);
    }
    printf("rank: %d, repeat: %d\n", rank, repeat);

    if (rank == 0) {
        server(repeat);
    }else{
        client(repeat);
    }
    end = clock();
    printf("\ntotal time cost: %f\n", double(end-start)*1000/CLOCKS_PER_SEC);
}