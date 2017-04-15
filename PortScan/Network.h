#pragma once

#include <WINDOWS.H>

BOOL GetHostAddress(__in LPCTSTR lpHostName, __out PIP4_ADDRESS lpAddress);
int ConnectScan(IP4_ADDRESS ipAddress, WORD wPort, UINT uTimeout);
int SYNScan(IP4_ADDRESS ipAddress, WORD wPort, UINT uTimeout);
void SYNReset(void *packet);

#define PORT_STATUS_CLOSED				0
#define PORT_STATUS_OPEN				1
#define PORT_STATUS_CLOSED_UNFILTERED	-1

#pragma pack(push)
#pragma pack(2)

typedef struct _ETHERNET2_HEADER
{
	UCHAR		et_dest[6];	/* Destination node */
	UCHAR		et_src[6];	/* Source node */
	USHORT		et_protlen;	/* Protocol or length */
} ETHERNET2_HEADER, *PETHERNET2_HEADER;

typedef struct _IP_HEADER
{
	UCHAR		ip_hl_v;	/* header length and version */
	UCHAR		ip_tos;		/* type of service */
	USHORT		ip_len;		/* total length */
	USHORT		ip_id;		/* identification */
	USHORT		ip_off;		/* fragment offset field */
	UCHAR		ip_ttl;		/* time to live */
	UCHAR		ip_p;		/* protocol */
	USHORT		ip_sum;		/* checksum */
	ULONG		ip_src;		/* Source IP address */
	ULONG		ip_dst;		/* Destination IP address */
} IP_HEADER, *PIP_HEADER;

typedef struct _TCP_HEADER
{
	USHORT		srcport;
	USHORT		destport;
	ULONG		seqno;
	ULONG		ackno;
	UCHAR		tcpoffset;
	UCHAR		flags;
	USHORT		wnd;
	USHORT		tcpchksum;
	USHORT		urgp;
} TCP_HEADER, *PTCP_HEADER;

typedef struct _FULL_TCP_PACKET
{
	ETHERNET2_HEADER eth;
	IP_HEADER ip;
	TCP_HEADER tcp;
	UCHAR opt[12];
} FULL_TCP_PACKET, *PFULL_TCP_PACKET;

#pragma pack(pop)

#define PROT_IP		0x0800		/* IP protocol */

#define TCP_FIN		0x01
#define TCP_SYN		0x02
#define TCP_RST		0x04
#define TCP_PSH		0x08
#define TCP_ACK		0x10
#define TCP_URG		0x20
#define TCP_CTL		0x3f
