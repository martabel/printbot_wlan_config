#include <string.h>

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

extern "C" {
    #include "lwip/pbuf.h"
    #include "lwip/tcp.h"

    #include "dhcpserver.h"
    #include "dnsserver.h"
}

#include "m24c0x/src/m24c0x.hpp"

#define TCP_PORT 80
#define HTTP_GET "GET"
#define HTTP_POST "POST /pb-set-wifi"
#define HTTP_RESPONSE_HEADERS "HTTP/1.1 %d OK\nContent-Length: %d\nContent-Type: text/html; charset=utf-8\nConnection: close\n\n"
#define HTML_BODY "<!doctypehtml><html lang=en><meta charset=UTF-8><meta content=\"width=device-width,initial-scale=1\"name=viewport><meta content=\"ie=edge\"http-equiv=X-UA-Compatible><title>PrintBot WLAN configuration</title><main><h1>PrintBot WLAN configuration</h1><h2>Actual Configuration</h2><p>WLAN SSID: %s<h2>Set new WLAN</h2><form action=\"pb-set-wifi\" method=\"post\"><label for=ssid>WLAN SSID:</label> <input id=ssid name=ssid><br><br><label for=password>Password:</label> <input id=password name=password><br><br><input type=submit value=\"Save & Connect\"></form></main>"
#define HTML_RESULT_BODY "<!doctypehtml><html lang=en><meta charset=UTF-8><meta content=\"width=device-width,initial-scale=1\"name=viewport><meta content=\"ie=edge\"http-equiv=X-UA-Compatible><title>PrintBot WLAN configuration</title><main><h1>New WLAN configuration saved. The system restart automaticlly</h1></main>"
#define BTN_GPIO 14

#define WLAN_CRED_BUFFER_SIZE 50
#define WLAN_CRED_SAVED_FLAG 0xA5
#define WLAN_SSID_DEFAULT "DEFAULT_SSID"
#define WLAN_PASSWORD_DEFAULT "DEFAULT_PW"

#define WLAN_AP_SSID "printbot"
#define WLAN_AP_PASSWORD "printbot"

#define I2C_PORT i2c0
#define I2C_SDA 4
#define I2C_SCL 5
#define WC_PIN 13   
#define I2C_ADDR 0x50

typedef struct TCP_SERVER_T_ {
    struct tcp_pcb *server_pcb;
    bool complete;
    ip_addr_t gw;
} TCP_SERVER_T;

typedef struct TCP_CONNECT_STATE_T_ {
    struct tcp_pcb *pcb;
    int sent_len;
    char headers[128];
    char result[1024];
    int header_len;
    int result_len;
    ip_addr_t *gw;
} TCP_CONNECT_STATE_T;

static char wifi_ssid[WLAN_CRED_BUFFER_SIZE];
static char wifi_password[WLAN_CRED_BUFFER_SIZE];
static bool wifi_is_saved = false;

static M24C0x eeprom(I2C_PORT, I2C_ADDR, I2C_SDA, I2C_SCL, WC_PIN);

void save_wlan_config_to_eeprom()
{
    printf("save credentials to eeprom\nssid: %s pw: %s\n", wifi_ssid, wifi_password);
    eeprom.write_bytes(0, (uint8_t*)wifi_ssid, WLAN_CRED_BUFFER_SIZE);
    eeprom.write_bytes(WLAN_CRED_BUFFER_SIZE, (uint8_t*)wifi_password, WLAN_CRED_BUFFER_SIZE);
    uint8_t savedFlag[1] = {WLAN_CRED_SAVED_FLAG};
    eeprom.write_bytes(2*WLAN_CRED_BUFFER_SIZE, savedFlag, 1);
    printf("save credentials to eeprom, done\n");
}

bool load_wlan_config_from_eeprom()
{
    printf("read credentials from eeprom\n");
    eeprom.read_bytes(0, (uint8_t*)wifi_ssid, WLAN_CRED_BUFFER_SIZE);
    eeprom.read_bytes(WLAN_CRED_BUFFER_SIZE, (uint8_t*)wifi_password, WLAN_CRED_BUFFER_SIZE);
    uint8_t savedFlag[1] = {0};
    eeprom.read_bytes(2*WLAN_CRED_BUFFER_SIZE, savedFlag, 1);
    printf("ssid: %s pw: %s flag: 0x%X\n", wifi_ssid, wifi_password, savedFlag[0]);
    if(savedFlag[0] == WLAN_CRED_SAVED_FLAG) {
        printf("Read credentials from eeprom successfully\n");
        return true;
    }else{
        printf("No valid credentials in eeprom found\n");
        return false;
    }
}

void clear_wlan_config_from_eeprom()
{
    printf("Clearing WLAN credentials from EEPROM\n");
    
    // Leere Arrays zum Überschreiben der Daten
    uint8_t empty_data[WLAN_CRED_BUFFER_SIZE];
    memset(empty_data, 0, WLAN_CRED_BUFFER_SIZE);
    
    // SSID und Passwort im EEPROM mit leeren Bytes überschreiben
    eeprom.write_bytes(0, empty_data, WLAN_CRED_BUFFER_SIZE);
    eeprom.write_bytes(WLAN_CRED_BUFFER_SIZE, empty_data, WLAN_CRED_BUFFER_SIZE);
    
    // Flag auf 0 setzen, damit beim nächsten Einlesen die Credentials als ungültig erkannt werden
    uint8_t clearedFlag[1] = {0};
    eeprom.write_bytes(2*WLAN_CRED_BUFFER_SIZE, clearedFlag, 1);
    
    // Lokale Variablen zurücksetzen
    memset(wifi_ssid, 0, WLAN_CRED_BUFFER_SIZE);
    memset(wifi_password, 0, WLAN_CRED_BUFFER_SIZE);
    
    printf("WLAN credentials successfully cleared\n");
}

int url_decode(char* out, const char* in)
{
    static const char tbl[256] = {
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
         (char)0,(char) 1,(char) 2,(char) 3,(char) 4,(char) 5,(char) 6,(char) 7,(char)  8,(char) 9,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)10,(char)11,(char)12,(char)13,(char)14,(char)15,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)10,(char)11,(char)12,(char)13,(char)14,(char)15,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,
        (char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char) -1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1,(char)-1
    };
    char c, v1, v2, *beg=out;
    if(in != NULL) {
        while((c=*in++) != '\0') {
            if(c == '%') {
                if((v1=tbl[(unsigned char)*in++])<0 || 
                   (v2=tbl[(unsigned char)*in++])<0) {
                    *beg = '\0';
                    return -1;
                }
                c = (v1<<4)|v2;
            }
            *out++ = c;
        }
    }
    *out = '\0';
    return 0;
}

static err_t tcp_close_client_connection(TCP_CONNECT_STATE_T *con_state, struct tcp_pcb *client_pcb, err_t close_err) {
    if (client_pcb) {
        assert(con_state && con_state->pcb == client_pcb);
        tcp_arg(client_pcb, NULL);
        tcp_poll(client_pcb, NULL, 0);
        tcp_sent(client_pcb, NULL);
        tcp_recv(client_pcb, NULL);
        tcp_err(client_pcb, NULL);
        err_t err = tcp_close(client_pcb);
        if (err != ERR_OK) {
            printf("close failed %d, calling abort\n", err);
            tcp_abort(client_pcb);
            close_err = ERR_ABRT;
        }
        if (con_state) {
            free(con_state);
        }
    }
    return close_err;
}

static void tcp_server_close(TCP_SERVER_T *state) {
    if (state->server_pcb) {
        tcp_arg(state->server_pcb, NULL);
        tcp_close(state->server_pcb);
        state->server_pcb = NULL;
    }
}

static err_t tcp_server_sent(void *arg, struct tcp_pcb *pcb, u16_t len) {
    TCP_CONNECT_STATE_T *con_state = (TCP_CONNECT_STATE_T*)arg;
    printf("tcp_server_sent %u\n", len);
    con_state->sent_len += len;
    if (con_state->sent_len >= con_state->header_len + con_state->result_len) {
        printf("all done\n");
        return tcp_close_client_connection(con_state, pcb, ERR_OK);
    }
    return ERR_OK;
}

static int wlan_config_server_content(const char *request, const char *params, char *result, size_t max_result_len) {
    int len = 0;
    len = snprintf(result, max_result_len, HTML_BODY, wifi_ssid);
    return len;
}


err_t tcp_server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    TCP_CONNECT_STATE_T *con_state = (TCP_CONNECT_STATE_T*)arg;
    if (!p) {
        printf("connection closed\n");
        return tcp_close_client_connection(con_state, pcb, ERR_OK);
    }
    assert(con_state && con_state->pcb == pcb);
    if (p->tot_len > 0) {
        printf("tcp_server_recv %d err %d\n", p->tot_len, err);

        bool send_response = false;

        // Copy the request into the buffer
        pbuf_copy_partial(p, con_state->headers, p->tot_len > sizeof(con_state->headers) - 1 ? sizeof(con_state->headers) - 1 : p->tot_len, 0);

        // Handle POST request
        if (strncmp(HTTP_POST, con_state->headers, sizeof(HTTP_POST) - 1) == 0) {
            if (p->tot_len < 1024)
            {
                char wifi_ssid_tmp[51];
                char wifi_pw_tmp[51];
                char payload[128];
                char *p_body = strstr((char*)(p->payload), "\r\n\r\n");
                uint p_body_length = p->tot_len - ((uint)p_body - (uint)(p->payload));
                memcpy(payload, p_body, p_body_length);
                payload[p_body_length] = 0;

                printf("POST body ", p_body);
                printf("\n");
                printf("POST body length ", p_body_length);
                printf("\n");

                // Scan the query string
                sscanf(payload, "\r\n\r\nssid=%50[^&]&password=%50[^&]", wifi_ssid_tmp, wifi_pw_tmp);

                // Clean old credentials
                for(int i=0; i<WLAN_CRED_BUFFER_SIZE; i++) {
                    wifi_ssid[i] = 0;
                    wifi_password[i] = 0;
                }

                // Decode
                url_decode(wifi_ssid, wifi_ssid_tmp);
                url_decode(wifi_password, wifi_pw_tmp);


                // gen result page
                con_state->result_len = snprintf(con_state->result, sizeof(con_state->result), HTML_RESULT_BODY);

                send_response = true;
                wifi_is_saved = true;
            }
        }

        // Handle GET request
        if (strncmp(HTTP_GET, con_state->headers, sizeof(HTTP_GET) - 1) == 0) {
            char *request = con_state->headers + sizeof(HTTP_GET); // + space
            char *params = strchr(request, '?');
            if (params) {
                if (*params) {
                    char *space = strchr(request, ' ');
                    *params++ = 0;
                    if (space) {
                        *space = 0;
                    }
                } else {
                    params = NULL;
                }
            }

            // Generate content
            //con_state->result_len = test_server_content(request, params, con_state->result, sizeof(con_state->result));
            con_state->result_len = wlan_config_server_content(request, params, con_state->result, sizeof(con_state->result));

            send_response = true;
        }

        if(send_response == true)
        {
            // Check we had enough buffer space
            if (con_state->result_len > sizeof(con_state->result) - 1) {
                printf("Too much result data %d\n", con_state->result_len);
                return tcp_close_client_connection(con_state, pcb, ERR_CLSD);
            }

            // Generate web page
            if (con_state->result_len > 0) {
                con_state->header_len = snprintf(con_state->headers, sizeof(con_state->headers), HTTP_RESPONSE_HEADERS,
                    200, con_state->result_len);
                if (con_state->header_len > sizeof(con_state->headers) - 1) {
                    printf("Too much header data %d\n", con_state->header_len);
                    return tcp_close_client_connection(con_state, pcb, ERR_CLSD);
                }
            }

            // Send the headers to the client
            con_state->sent_len = 0;
            err_t err = tcp_write(pcb, con_state->headers, con_state->header_len, 0);
            if (err != ERR_OK) {
                printf("failed to write header data %d\n", err);
                return tcp_close_client_connection(con_state, pcb, err);
            }

            // Send the body to the client
            if (con_state->result_len) {
                err = tcp_write(pcb, con_state->result, con_state->result_len, 0);
                if (err != ERR_OK) {
                    printf("failed to write result data %d\n", err);
                    return tcp_close_client_connection(con_state, pcb, err);
                }
            }
        }
        tcp_recved(pcb, p->tot_len);
    }
    pbuf_free(p);
    return ERR_OK;
}


static void tcp_server_err(void *arg, err_t err) {
    TCP_CONNECT_STATE_T *con_state = (TCP_CONNECT_STATE_T*)arg;
    if (err != ERR_ABRT) {
        printf("tcp_client_err_fn %d\n", err);
        tcp_close_client_connection(con_state, con_state->pcb, err);
    }
}

static err_t tcp_server_accept(void *arg, struct tcp_pcb *client_pcb, err_t err) {
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
    if (err != ERR_OK || client_pcb == NULL) {
        printf("failure in accept\n");
        return ERR_VAL;
    }
    printf("client connected\n");

    // Create the state for the connection
    TCP_CONNECT_STATE_T *con_state = (TCP_CONNECT_STATE_T*)calloc(1, sizeof(TCP_CONNECT_STATE_T));
    if (!con_state) {
        printf("failed to allocate connect state\n");
        return ERR_MEM;
    }
    con_state->pcb = client_pcb; // for checking
    con_state->gw = &state->gw;

    // setup connection to client
    tcp_arg(client_pcb, con_state);
    tcp_sent(client_pcb, tcp_server_sent);
    tcp_recv(client_pcb, tcp_server_recv);
    tcp_err(client_pcb, tcp_server_err);

    return ERR_OK;
}

static bool tcp_server_open(void *arg, const char *ap_name) {
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
    printf("starting server on port %d\n", TCP_PORT);

    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!pcb) {
        printf("failed to create pcb\n");
        return false;
    }

    err_t err = tcp_bind(pcb, IP_ANY_TYPE, TCP_PORT);
    if (err) {
        printf("failed to bind to port %d\n",TCP_PORT);
        return false;
    }

    state->server_pcb = tcp_listen_with_backlog(pcb, 1);
    if (!state->server_pcb) {
        printf("failed to listen\n");
        if (pcb) {
            tcp_close(pcb);
        }
        return false;
    }

    tcp_arg(state->server_pcb, state);
    tcp_accept(state->server_pcb, tcp_server_accept);

    return true;
}

int main() {

    stdio_init_all();
    
    sleep_ms(4000);

    eeprom.init();

    TCP_SERVER_T *state = (TCP_SERVER_T*)calloc(1, sizeof(TCP_SERVER_T));
    if (!state) {
        printf("failed to allocate state\n");
        return 1;
    }

    if (cyw43_arch_init()) {
        printf("failed to initialise\n");
        return 1;
    }

    cyw43_arch_enable_ap_mode(WLAN_AP_SSID, WLAN_AP_PASSWORD, CYW43_AUTH_WPA2_AES_PSK);

    ip4_addr_t mask;
    IP4_ADDR(ip_2_ip4(&state->gw), 192, 168, 4, 1);
    IP4_ADDR(ip_2_ip4(&mask), 255, 255, 255, 0);

    // Start the dhcp server
    dhcp_server_t dhcp_server;
    dhcp_server_init(&dhcp_server, &state->gw, &mask);

    // Start the dns server
    dns_server_t dns_server;
    dns_server_init(&dns_server, &state->gw);

    if (!tcp_server_open(state, WLAN_AP_SSID)) {
        printf("failed to open server\n");
        return 1;
    }

    // button init
    gpio_init(BTN_GPIO);
    gpio_set_dir(BTN_GPIO, GPIO_IN);

    // UART0 initialisieren (TX ist GP0, RX ist GP1)
    uart_init(uart0, 115200);
    gpio_set_function(0, GPIO_FUNC_UART); // TX
    gpio_set_function(1, GPIO_FUNC_UART); // RX
    uart_set_format(uart0, 8, 1, UART_PARITY_NONE);

    printf("\n########\nPRINTBOT\n########\n\n");

    state->complete = false;

    // init and copy default wifi credentials
    for(int i=0; i<WLAN_CRED_BUFFER_SIZE; i++){
        wifi_ssid[i] = 0;
        wifi_password[i] = 0;
    }

    wifi_is_saved = load_wlan_config_from_eeprom();

    while(!state->complete) {

        while (true) {
            if (gpio_get(BTN_GPIO) == 1) {
                    printf("AP button pressed\n");
                    printf("Activate AP mode and delete saved credentials\n");
                    clear_wlan_config_from_eeprom();
                    // client off, ap on
                    cyw43_arch_disable_sta_mode();
                    sleep_ms(50);
                    cyw43_arch_enable_ap_mode(WLAN_AP_SSID, WLAN_AP_PASSWORD, CYW43_AUTH_WPA2_AES_PSK);
                    printf("AP mode active\n");
            }
            if (wifi_is_saved)
            {
                printf("Try to connect to saved wlan settings\n");
                wifi_is_saved = false;

                sleep_ms(500);

                cyw43_arch_disable_ap_mode();

                sleep_ms(500);

                cyw43_arch_enable_sta_mode();

                if (cyw43_arch_wifi_connect_timeout_ms(wifi_ssid, wifi_password, CYW43_AUTH_WPA2_AES_PSK, 15000)) {
                    printf("connection to wifi not ok\n");
                    // connection to wifi not ok
                    printf("activate AP mode\n");
                    // go again to ap mode
                    cyw43_arch_disable_sta_mode();
                    sleep_ms(500);
                    cyw43_arch_enable_ap_mode(WLAN_AP_SSID, WLAN_AP_PASSWORD, CYW43_AUTH_WPA2_AES_PSK);
                    
                }
                else
                {
                    printf("connection to wifi ok\n");

                    // Get and print IP address
                    printf("IP Address: %s\n", ip4addr_ntoa(netif_ip4_addr(&cyw43_state.netif[CYW43_ITF_STA])));

                    // save to eeprom
                    save_wlan_config_to_eeprom();
                }
            }
            sleep_ms(1);
        }
    }
    tcp_server_close(state);
    dns_server_deinit(&dns_server);
    dhcp_server_deinit(&dhcp_server);
    cyw43_arch_deinit();
    return 0;
}
