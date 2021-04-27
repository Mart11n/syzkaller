#include <errno.h>
#include <fcntl.h>
#include <linux/rfkill.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>

// macros and structs
#ifndef _SYZKALL_UTIL
#define _SYZKALL_UTIL
#define bool uint8
#define true 1
#define false 0

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

struct sockaddr_hci {
        unsigned short hci_family;
        unsigned short hci_dev;
        unsigned short hci_channel;
};

#define BTPROTO_HCI 1
#define ACL_LINK 1
#define SCAN_PAGE 2

typedef struct {
        uint8 b[6];
} __attribute__((packed)) bdaddr_t;

#define HCI_COMMAND_PKT 1
#define HCI_EVENT_PKT 4
#define HCI_VENDOR_PKT 0xff

#define HCI_OP_RESET 0x0c03
#define HCI_OP_SET_EVENT_FLT 0x0c05
#define HCI_OP_WRITE_CA_TIMEOUT		0x0c16

struct hci_command_hdr {
        uint16 opcode;
        uint8 plen;
} __attribute__((packed));

struct hci_event_hdr {
        uint8 evt;
        uint8 plen;
} __attribute__((packed));

#define HCI_EV_CONN_COMPLETE 0x03
struct hci_ev_conn_complete {
        uint8 status;
        uint16 handle;
        bdaddr_t bdaddr;
        uint8 link_type;
        uint8 encr_mode;
} __attribute__((packed));

#define HCI_OP_READ_LOCAL_VERSION 0x1001
struct hci_rp_read_local_version {
        __u8 status;
        __u8 hci_ver;
        __le16 hci_rev;
        __u8 lmp_ver;
        __le16 manufacturer;
        __le16 lmp_subver;
} __attribute__((packed));

#define HCI_OP_LE_READ_BUFFER_SIZE 0x2002
struct hci_rp_le_read_buffer_size {
        __u8 status;
        __le16 le_mtu;
        __u8 le_max_pkt;
} __attribute__((packed));

struct hci_dev_req {
        uint16 dev_id;
        uint32 dev_opt;
};

struct vhci_vendor_pkt {
        uint8 type;
        uint8 opcode;
        uint16 id;
};

#define HCI_OP_READ_CLASS_OF_DEV 0x0c23
struct hci_rp_read_class_of_dev {
        __u8 status;
        __u8 dev_class[3];
} __attribute__((packed));

#define HCI_OP_READ_LOCAL_FEATURES 0x1003
struct hci_rp_read_local_features {
        __u8 status;
        __u8 features[8];
} __attribute__((packed));

#define HCI_OP_READ_BD_ADDR 0x1009
struct hci_rp_read_bd_addr {
        uint8 status;
        bdaddr_t bdaddr;
} __attribute__((packed));

#define HCI_EV_LE_META 0x3e
struct hci_ev_le_meta {
        uint8 subevent;
} __attribute__((packed));

#define HCI_EV_LE_CONN_COMPLETE 0x01
struct hci_ev_le_conn_complete {
        uint8 status;
        uint16 handle;
        uint8 role;
        uint8 bdaddr_type;
        bdaddr_t bdaddr;
        uint16 interval;
        uint16 latency;
        uint16 supervision_timeout;
        uint8 clk_accurancy;
} __attribute__((packed));

#define HCI_EV_CONN_REQUEST 0x04
struct hci_ev_conn_request {
        bdaddr_t bdaddr;
        uint8 dev_class[3];
        uint8 link_type;
} __attribute__((packed));

#define HCI_EV_REMOTE_FEATURES 0x0b
struct hci_ev_remote_features {
        uint8 status;
        uint16 handle;
        uint8 features[8];
} __attribute__((packed));

#define HCI_EV_CMD_COMPLETE 0x0e
struct hci_ev_cmd_complete {
        uint8 ncmd;
        uint16 opcode;
} __attribute__((packed));

#define HCI_OP_WRITE_SCAN_ENABLE 0x0c1a

#define HCI_OP_READ_BUFFER_SIZE 0x1005
struct hci_rp_read_buffer_size {
        uint8 status;
        uint16 acl_mtu;
        uint8 sco_mtu;
        uint16 acl_max_pkt;
        uint16 sco_max_pkt;
} __attribute__((packed));

struct vparam {
	int fd;
	int sock;
	uint16 id;
};

#define HCIDEVUP _IOW('H', 201, int)
#define HCISETSCAN _IOW('H', 221, int)
#define HCIINQUIRY	_IOR('H', 240, int)

#define fail(x) perror(x),exit(1)
// functions
void hci_send_event_cmd_complete(int fd, uint16 opcode, void* data, size_t data_len);
void hci_send_event_packet(int fd, uint8 evt, void* data, size_t data_len);
struct vparam initialize_vhci();

#endif
