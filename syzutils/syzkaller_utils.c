#include "syzkaller_utils.h"

void hci_send_event_cmd_complete(int fd, uint16 opcode, void* data, size_t data_len)
{
        struct iovec iv[4];

        struct hci_event_hdr hdr;
        hdr.evt = HCI_EV_CMD_COMPLETE;
        hdr.plen = sizeof(struct hci_ev_cmd_complete) + data_len;

        struct hci_ev_cmd_complete evt_hdr;
        evt_hdr.ncmd = 1;
        evt_hdr.opcode = opcode;

        uint8 type = HCI_EVENT_PKT;

        iv[0].iov_base = &type;
        iv[0].iov_len = sizeof(type);
        iv[1].iov_base = &hdr;
        iv[1].iov_len = sizeof(hdr);
        iv[2].iov_base = &evt_hdr;
        iv[2].iov_len = sizeof(evt_hdr);
        iv[3].iov_base = data;
        iv[3].iov_len = data_len;

        if (writev(fd, iv, sizeof(iv) / sizeof(struct iovec)) < 0)
                fail("writev failed");
}

void hci_send_event_packet(int fd, uint8 evt, void* data, size_t data_len)
{
        struct iovec iv[3];

        struct hci_event_hdr hdr;
        hdr.evt = evt;
        hdr.plen = data_len;

        uint8 type = HCI_EVENT_PKT;

        iv[0].iov_base = &type;
        iv[0].iov_len = sizeof(type);
        iv[1].iov_base = &hdr;
        iv[1].iov_len = sizeof(hdr);
        iv[2].iov_base = data;
        iv[2].iov_len = data_len;

        if (writev(fd, iv, sizeof(iv) / sizeof(struct iovec)) < 0)
                fail("writev failed");
}

static bool process_command_pkt(int fd, char* buf, ssize_t buf_size)
{
        struct hci_command_hdr* hdr = (struct hci_command_hdr*)buf;
        if (buf_size < (ssize_t)sizeof(struct hci_command_hdr) ||
            hdr->plen != buf_size - sizeof(struct hci_command_hdr)) {
                fail("process_command_pkt: invalid size");
        }

	// printf("[+] proccsing command opcode: %x\n", hdr->opcode);
	bool retornot = false;

        switch (hdr->opcode) {
	case HCI_OP_WRITE_CA_TIMEOUT: {
                retornot = true;
		break;
        }
        case HCI_OP_READ_BD_ADDR: {
                struct hci_rp_read_bd_addr rp = {0};
                rp.status = 0;
                memset(&rp.bdaddr, 0xaa, 6);
                hci_send_event_cmd_complete(fd, hdr->opcode, &rp, sizeof(rp));
                return false;
        }
        case HCI_OP_READ_BUFFER_SIZE: {
                struct hci_rp_read_buffer_size rp = {0};
                rp.status = 0;
                rp.acl_mtu = 1021;
                rp.sco_mtu = 96;
                rp.acl_max_pkt = 4;
                rp.sco_max_pkt = 6;
                hci_send_event_cmd_complete(fd, hdr->opcode, &rp, sizeof(rp));
                return false;
        }
        }

        char dummy[0xf9] = {0};
        hci_send_event_cmd_complete(fd, hdr->opcode, dummy, sizeof(dummy));
        if (!retornot) return false;
	else return true;
}


static void* event_thread(void* arg)
{
	int vhci_fd = *(int*)arg;
        while (1) {
                char buf[1024] = {0};
                ssize_t buf_size = read(vhci_fd, buf, sizeof(buf));
                if (buf_size < 0)
                        fail("read failed");
                if (buf_size > 0 && buf[0] == HCI_COMMAND_PKT) {
                        if (process_command_pkt(vhci_fd, buf + 1, buf_size - 1))
                                break;
                }
        }
        return NULL;
}

struct vparam initialize_vhci()
{
	struct vparam resultp;
#if SYZ_EXECUTOR
        if (!flag_vhci_injection)
                return;
#endif

        int hci_sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
        if (hci_sock < 0)
                fail("socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI) failed");

	resultp.sock = hci_sock;

        int vhci_fd = open("/dev/vhci", O_RDWR);
        if (vhci_fd == -1)
                fail("open /dev/vhci failed");

	resultp.fd = vhci_fd;

        struct vhci_vendor_pkt vendor_pkt;
        if (read(vhci_fd, &vendor_pkt, sizeof(vendor_pkt)) != sizeof(vendor_pkt))
                fail("read failed");

        if (vendor_pkt.type != HCI_VENDOR_PKT)
                fail("wrong response packet");

        printf("[+] hci dev id: %x\n", vendor_pkt.id);
	
	resultp.id = vendor_pkt.id;

        pthread_t th;
        if (pthread_create(&th, NULL, event_thread, &vhci_fd))
                fail("pthread_create failed");

        // Bring hci device up
        int ret = ioctl(hci_sock, HCIDEVUP, vendor_pkt.id);

        if (ret) {
                if (ret && errno != EALREADY)
                        fail("ioctl(HCIDEVUP) failed");
        }

 	// The sad thing is scanning mode requires admin privilege
	pthread_join(th, NULL);
	// I think don't have to create any connection..
	printf("[+] device hci-%d init done\n", resultp.id);
	return resultp;
} 


int main(){
    struct vparam resultp;
#if SYZ_EXECUTOR
        if (!flag_vhci_injection)
                return;
#endif

    int hci_sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (hci_sock < 0)
            fail("socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI) failed");

    resultp.sock = hci_sock;

    int vhci_fd = open("/dev/vhci", O_RDWR);
    if (vhci_fd == -1)
            fail("open /dev/vhci failed");

    resultp.fd = vhci_fd;

    struct vhci_vendor_pkt vendor_pkt;
    if (read(vhci_fd, &vendor_pkt, sizeof(vendor_pkt)) != sizeof(vendor_pkt))
            fail("read failed");

    if (vendor_pkt.type != HCI_VENDOR_PKT)
            fail("wrong response packet");

    printf("[+] hci dev id: %x\n", vendor_pkt.id);

    resultp.id = vendor_pkt.id;

    pthread_t th;
    if (pthread_create(&th, NULL, event_thread, &vhci_fd))
            fail("pthread_create failed");

    // Bring hci device up
    int ret = ioctl(hci_sock, HCIDEVUP, vendor_pkt.id);

    if (ret) {
            if (ret && errno != EALREADY)
                    fail("ioctl(HCIDEVUP) failed");
    }

    // The sad thing is scanning mode requires admin privilege
    pthread_join(th, NULL);
    // I think don't have to create any connection..
    printf("[+] device hci-%d init done\n", resultp.id);
    return 0;
}
