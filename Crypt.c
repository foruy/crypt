#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include "Crypt.h"

struct Msg {
	bool enc;
	char *header;
	int hlen;
	char *data;
	int dlen;
};

void close_device(int fd)
{
	if (fd > 0)
		close(fd);
}

static int open_device(char *dev)
{
	int fd, err;
	struct ifreq ifr;

	if ((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0) {
		perror("Cannot Open Device");
		return fd;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		perror("Cannot TUNSETIFF");
		close_device(fd);
		return err;
	}

	//strcpy(dev, ifr.ifr_name);
	return fd;
}

static int write_data(int fd, struct Msg *msg)
{
	char *wptr;
	int bytes_write, rest_write = msg->hlen + msg->dlen;
	char buf[rest_write];

	memcpy(buf, msg->header, msg->hlen);
	memcpy(buf + msg->hlen, msg->data, msg->dlen);
	wptr = buf;

	while (rest_write > 0) {
		bytes_write = write(fd, wptr, rest_write);

		if (bytes_write < 0)
			return -1;

		rest_write -= bytes_write;
		wptr += bytes_write;
	}
}

static void read_data(int fd, int wfd, bool enc, struct Msg *msg)
{
	struct ethhdr *ehdr;
	int bytes_read, bytes_write;
	int total_read =0 , rest_write = 0;
	char writebuf[BUF_SIZE * 3];
	char readbuf[BUF_SIZE];

	memset(readbuf, 0, BUF_SIZE);
	memset(writebuf, 0, BUF_SIZE * 3);

	while (bytes_read = read(fd, readbuf, BUF_SIZE)) {
printf("read bytes: %d\n", bytes_read);
		if (bytes_read < 0 && errno != EINTR)
			break;

		memcpy(writebuf + total_read, readbuf, bytes_read);
		total_read += bytes_read;

		if (bytes_read < BUF_SIZE)
			break;
	}

	ehdr = (struct ethhdr *) writebuf;

	// Encrypt and Decrypt if ip packet, and redirected for arp packet,
        // else dropped
	if (ntohs(ehdr->h_proto) == ETH_P_IP) {
		msg->enc = enc;
		msg->header = (char *) ehdr;
		msg->hlen = sizeof(struct ethhdr) + sizeof(struct iphdr);
		msg->data = writebuf + msg->hlen;
		msg->dlen = total_read - msg->hlen;
	} else if (ntohs(ehdr->h_proto) == ETH_P_ARP) {
		struct Msg tmp;
		tmp.enc = enc;
		tmp.header = (char *) ehdr;
		tmp.hlen = sizeof(struct ethhdr);
		tmp.data = (char *) (writebuf + tmp.hlen);
		tmp.dlen = total_read - tmp.hlen;
		write_data(wfd, &tmp);
	}
}

static int listen_data(int sfd, int cfd, struct Msg *msg)
{
	int ret, maxfd;
	fd_set fdset;
	struct timeval timeout;

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	FD_ZERO(&fdset);
	FD_SET(sfd, &fdset);
	FD_SET(cfd, &fdset);
	maxfd = (sfd > cfd) ? (sfd + 1) : (cfd + 1);
	ret = select(maxfd, &fdset, NULL, NULL, &timeout);
	if (ret > 0) {
		if (FD_ISSET(sfd, &fdset)) {
			printf("Decrypt\n");
			read_data(sfd, cfd, false, msg);
		} else if (FD_ISSET(cfd, &fdset)) {
			printf("Encrypt\n");
			read_data(cfd, sfd, true, msg);
		} else {
			printf("Undefined operation\n");
			ret = -1;
		}
	}

	/*if (ret <= 0) {
		msg->header = "";
		msg->data = "";
	}*/
	return ret;
}

JNIEXPORT jobject JNICALL Java_Crypt_openDevice (JNIEnv *env, jclass obj)
{
	jclass chcls = (*env)->FindClass(env, "Chan");
	jfieldID sid = (*env)->GetFieldID(env, chcls, "server", "I");
	jfieldID cid = (*env)->GetFieldID(env, chcls, "client", "I");
	int sfd = open_device(TAPSERVER);
	int cfd = open_device(TAPCLIENT);

	jobject mobj = (*env)->AllocObject(env, chcls);
	(*env)->SetIntField(env, mobj, sid, sfd);
	(*env)->SetIntField(env, mobj, cid, cfd);

	if (sfd < 0 || cfd < 0) {
		close_device(sfd);
		close_device(cfd);
	}

        return mobj;
}

JNIEXPORT jobject JNICALL Java_Crypt_readData(JNIEnv *env, jclass obj, jobject ch)
{
	//jclass chcls = (*env)->FindClass(env, "Chan");
	jclass chcls = (*env)->GetObjectClass(env, ch);
	jfieldID sid = (*env)->GetFieldID(env, chcls, "server", "I");
	jfieldID cid = (*env)->GetFieldID(env, chcls, "client", "I");
	int server = (int)(*env)->GetIntField(env, ch, sid);
	int client = (int)(*env)->GetIntField(env, ch, cid);

	struct Msg msg;
	memset(&msg, 0, sizeof(msg));
	listen_data(server, client, &msg);

        jbyteArray harr = (*env)->NewByteArray(env, msg.hlen);
        (*env)->SetByteArrayRegion(env, harr, 0, msg.hlen, msg.header);
        jbyteArray darr = (*env)->NewByteArray(env, msg.dlen);
        (*env)->SetByteArrayRegion(env, darr, 0, msg.dlen, msg.data);

        jclass cls = (*env)->FindClass(env, "Message");
        jfieldID eid = (*env)->GetFieldID(env, cls, "enc", "Z");
        jfieldID hid = (*env)->GetFieldID(env, cls, "header", "[B");
        jfieldID did = (*env)->GetFieldID(env, cls, "data", "[B");

	jobject mobj = (*env)->AllocObject(env, cls);
        (*env)->SetBooleanField(env, mobj, eid, msg.enc);
        (*env)->SetObjectField(env, mobj, hid, harr);
        (*env)->SetObjectField(env, mobj, did, darr);
        return mobj;
}

JNIEXPORT void JNICALL Java_Crypt_writeData(JNIEnv *env, jclass obj, jobject ch, jobject jmsg)
{
        //jclass chcls = (*env)->FindClass(env, "Chan");
	jclass chcls = (*env)->GetObjectClass(env, ch);
        jfieldID sid = (*env)->GetFieldID(env, chcls, "server", "I");
        jfieldID cid = (*env)->GetFieldID(env, chcls, "client", "I");
        int server = (*env)->GetIntField(env, ch, sid);
        int client = (*env)->GetIntField(env, ch, cid);

        //jclass cls = (*env)->FindClass(env, "Message");
	jclass cls = (*env)->GetObjectClass(env, jmsg);
        jfieldID eid = (*env)->GetFieldID(env, cls, "enc", "Z");
        jfieldID hid = (*env)->GetFieldID(env, cls, "header", "[B");
        jfieldID did = (*env)->GetFieldID(env, cls, "data", "[B");

	struct Msg msg;
        jbyteArray harr = (*env)->GetObjectField(env, jmsg, hid);
        jbyteArray darr = (*env)->GetObjectField(env, jmsg, did);
	msg.enc = (*env)->GetBooleanField(env, jmsg, eid);
        msg.header = (*env)->GetByteArrayElements(env, harr, JNI_FALSE);
	msg.hlen = (*env)->GetArrayLength(env, harr);
        msg.data = (*env)->GetByteArrayElements(env, darr, JNI_FALSE);
	msg.dlen = (*env)->GetArrayLength(env, darr);

	if (msg.enc)
		write_data(server, &msg);
	else
		write_data(client, &msg);

        (*env)->ReleaseByteArrayElements(env, harr, msg.header, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, darr, msg.data, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_Crypt_closeDevice(JNIEnv *env, jclass obj, jobject ch)
{
	jclass chcls = (*env)->FindClass(env, "Chan");
	jfieldID sid = (*env)->GetFieldID(env, chcls, "server", "I");
	jfieldID cid = (*env)->GetFieldID(env, chcls, "client", "I");
	int server = (*env)->GetIntField(env, ch, sid);
	int client = (*env)->GetIntField(env, ch, cid);

	close_device(server);
	close_device(client);
}
