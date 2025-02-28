#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>

#define SSDP_MULTICAST_ADDRESS "239.255.255.250"
#define SSDP_MULTICAST_PORT 1900
#define MAX_BUFFER_LEN 8192

static const char ssdp_discover_string[] =
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n";

#define MAX_IPS 1000
char discovered_ips[MAX_IPS][INET_ADDRSTRLEN];
int discovered_ips_count = 0;

int is_ip_discovered(const char *ip) {
    for (int i = 0; i < discovered_ips_count; i++) {
        if (strcmp(discovered_ips[i], ip) == 0) {
            return 1; // IP already discovered
        }
    }
    return 0; // IP not discovered
}

void add_discovered_ip(const char *ip) {
    if (discovered_ips_count < MAX_IPS) {
        strncpy(discovered_ips[discovered_ips_count], ip, INET_ADDRSTRLEN);
        discovered_ips_count++;
    }
}

void discover_hosts(const char *interface_ip);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface_ip> [<interface_ip> ...]\n", argv[0]);
        return 1;
    }
    
    for (int i = 1; i < argc; i++) {
        discover_hosts(argv[i]);
    }
    
    return 0;
}

void discover_hosts(const char *interface_ip) {
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket()");
        return;
    }
    
    struct sockaddr_in src_sock = {0};
    src_sock.sin_family = AF_INET;
    src_sock.sin_addr.s_addr = inet_addr(interface_ip);
    src_sock.sin_port = htons(0);
    
    if (bind(sock, (struct sockaddr *)&src_sock, sizeof(src_sock)) < 0) {
        perror("bind()");
        close(sock);
        return;
    }
    
    struct sockaddr_in dest_sock = {0};
    dest_sock.sin_family = AF_INET;
    dest_sock.sin_port = htons(SSDP_MULTICAST_PORT);
    inet_pton(AF_INET, SSDP_MULTICAST_ADDRESS, &dest_sock.sin_addr);
    
    sendto(sock, ssdp_discover_string, strlen(ssdp_discover_string), 0,
           (struct sockaddr *)&dest_sock, sizeof(dest_sock));
    
    struct sockaddr_in host_sock;
    socklen_t host_sock_len = sizeof(host_sock);
    char buffer[MAX_BUFFER_LEN];
    fd_set read_fds;
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    
    while (select(sock + 1, &read_fds, NULL, NULL, &timeout) > 0) {
        int bytes_in = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                                (struct sockaddr *)&host_sock, &host_sock_len);
        if (bytes_in > 0) {
            buffer[bytes_in] = '\0';
            if (strncmp(buffer, "HTTP/1.1 200 OK", 12) == 0) {
                const char *host_ip = inet_ntoa(host_sock.sin_addr);
                if (!is_ip_discovered(host_ip)) {
                    printf("%s\n", host_ip);
                    add_discovered_ip(host_ip);
                }
            }
        }
    }
    
    close(sock);
}

