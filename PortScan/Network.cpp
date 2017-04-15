#include "stdafx.h"

#include "Network.h"
#include "ScanWork.h"

static BOOL StringToAddress(__in LPCTSTR lpString, __out PIP4_ADDRESS lpAddress);

static USHORT ip_chksum(UCHAR *sdata, USHORT len);
static USHORT tcp_chksum(UCHAR *tcp_buf, UCHAR *src_ip, UCHAR *dst_ip, USHORT len);

BOOL GetHostAddress(__in LPCTSTR lpHostName, __out PIP4_ADDRESS lpAddress)
{
	PDNS_RECORD pDnsRecord, p;
	LPTSTR pCName = NULL;
	BOOL bQueryOK = FALSE;
	int nRetryCount = 3;

	if (StringToAddress(lpHostName, lpAddress))
		return TRUE;

	do
	{
		if (DnsQuery(lpHostName, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pDnsRecord, NULL) != ERROR_SUCCESS)
			return FALSE;

		if (pCName)
		{
			free(pCName);
			pCName = NULL;
		}

		p = pDnsRecord;

		while (p && !bQueryOK)
		{
			switch (p->wType)
			{
			case DNS_TYPE_A:
				*lpAddress = p->Data.A.IpAddress;
				bQueryOK = TRUE;
				break;

			case DNS_TYPE_CNAME:
				if (!pCName)
					pCName = _tcsdup(p->Data.CNAME.pNameHost);
			}

			p = p->pNext;
		}

		DnsRecordListFree(pDnsRecord, DnsFreeRecordListDeep);

		if (bQueryOK)
			break;

		if (pCName)
			lpHostName = pCName;

	} while (nRetryCount--);

	if (pCName)
		free(pCName);

	return TRUE;
}

static BOOL StringToAddress(__in LPCTSTR lpString, __out PIP4_ADDRESS lpAddress)
{
	int f[4];
	LPTSTR lpPtr = const_cast<LPTSTR>(lpString), lpNext;

	for (int i = 0; i < 4; i++)
	{
		f[i] = _tcstol(lpPtr, &lpNext, 0);

		if (lpPtr == lpNext)
			return FALSE;

		if ((i < 3) && (*lpNext != '.'))
			return FALSE;

		if ((f[i] < 0) || (f[i] > 255))
			return FALSE;
		
		lpPtr = lpNext;

		if (i < 3)
			lpPtr++;
	}

	if (*lpPtr)
		return FALSE;

	*lpAddress = (f[3] << 24) | (f[2] << 16) | (f[1] << 8) | f[0];

	return TRUE;
}

int ConnectScan(IP4_ADDRESS ipAddress, WORD wPort, UINT uTimeout)
{
	SOCKET s;
	sockaddr_in sin;
	u_long uNonBlock = 1;
	fd_set readset, writeset;
	linger l;
	TIMEVAL t;
	int err, ret, check = 0;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (s == INVALID_SOCKET)
		return PORT_STATUS_CLOSED;

	// 设置非阻塞 IO
	ioctlsocket(s, FIONBIO, &uNonBlock);

	memset(&sin, 0, sizeof (sin));

	sin.sin_addr.S_un.S_addr = ipAddress;
	sin.sin_family = AF_INET;
	sin.sin_port = wPort;

	do
	{
		if (connect(s, (sockaddr *) &sin, sizeof (sin)) == 0)
			break;

		err = WSAGetLastError();

		switch (err)
		{
		case WSAEINTR:
		case WSAEWOULDBLOCK:
		case WSAEINPROGRESS:
			// connect 正在进行
			if (check)
			{
				closesocket(s);
				return PORT_STATUS_CLOSED;
			}
			break;
		case WSAEALREADY:
		case WSAEISCONN:
		case WSAEINVAL: // Windows 2003 上的奇怪问题。。
			// connect 已成功
			goto _connected;
		default:
			// 当前地址的 connect 失败
			closesocket(s);
			return PORT_STATUS_CLOSED;
		}

		t.tv_sec = uTimeout;
		t.tv_usec = 0;

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_SET(s, &readset);
		FD_SET(s, &writeset);

		// 查询 socket 状态
		ret = select(s + 1, &readset, &writeset, NULL, &t);

		if (ret == SOCKET_ERROR)
		{
			closesocket(s);
			return PORT_STATUS_CLOSED;
		}

		if (ret > 0)
		{
			// 如果 socket 可写，则表明 connect 已成功，需要再次用 connect 函数去判断
			// 如果 socket 可读，则也去尝试
			if (FD_ISSET(s, &readset) || FD_ISSET(s, &writeset))
			{
				check = 1;
				continue;
			}
		}

		// 连接超时
		closesocket(s);
		return PORT_STATUS_CLOSED;

	} while (1);

_connected:

	// 以 RST 方式关闭连接
	l.l_onoff = 1;
	l.l_linger = 0;
	setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *) &l, sizeof (linger));

	closesocket(s);

	return PORT_STATUS_OPEN;
}

BOOL IsPortAvailable(WORD wPort)
{
	SOCKET s;
	BOOL bResult;
	sockaddr_in sin;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (s == INVALID_SOCKET)
		return FALSE;

	memset(&sin, 0, sizeof (sin));

	sin.sin_addr.S_un.S_addr = dwUnicastAddr;
	sin.sin_family = AF_INET;
	sin.sin_port = wPort;

	bResult = bind(s, (sockaddr *) &sin, sizeof (sin)) == 0;

	closesocket(s);

	return bResult;
}

int SYNScan(IP4_ADDRESS ipAddress, WORD wPort, UINT uTimeout)
{
	FULL_TCP_PACKET data;
	WORD wSrcPort;
	DWORD dwSeqNo;
	DWORD dwTick;

	memset(&data, 0, sizeof (data));

	memcpy(data.eth.et_dest, pGatewayMACAddr, 6);
	memcpy(data.eth.et_src, pAdapterMACAddr, 6);
	data.eth.et_protlen = htons(PROT_IP);

	data.ip.ip_hl_v  = 0x45;
	data.ip.ip_tos   = 0;
	data.ip.ip_len   = htons(sizeof (IP_HEADER) + sizeof (TCP_HEADER) + sizeof (data.opt));
	data.ip.ip_id    = htons(0x1000 + rand() % 0xefff);
	data.ip.ip_off   = htons(0x4000);
	data.ip.ip_ttl   = 128;
	data.ip.ip_p     = IPPROTO_TCP;
	data.ip.ip_sum   = 0;
	data.ip.ip_src   = dwUnicastAddr;
	data.ip.ip_dst   = ipAddress;
	data.ip.ip_sum   = ~ip_chksum((UCHAR *) &data.ip, sizeof (IP_HEADER));

	do
	{
		wSrcPort = GetNextPort();
	} while (!IsPortAvailable(htons(wSrcPort)));

	dwSeqNo = ((rand() & 0xffff) << 16) | (rand() & 0xffff);
	data.tcp.srcport = htons(wSrcPort);
	data.tcp.destport = wPort;
	data.tcp.seqno = htonl(dwSeqNo);
	data.tcp.ackno = 0;
	data.tcp.tcpoffset = ((5 + sizeof (data.opt) / 4)) << 4;
	data.tcp.flags = TCP_SYN;
	data.tcp.wnd = htons(8192);
	data.tcp.urgp = 0;

	memcpy(data.opt, "\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02", 12);

	data.tcp.tcpchksum = ~tcp_chksum((UCHAR *) &data.tcp, (UCHAR *) &dwUnicastAddr, (UCHAR *) &ipAddress, sizeof (TCP_HEADER) + sizeof (data.opt));

	PortCheckSet(wSrcPort, dwSeqNo);

	pcap_sendpacket(pcap_dev, (PUCHAR) &data, sizeof (data));

	dwTick = GetTickCount();

	while (!PortAliveIsSet(ntohs(wPort)))
	{
		if (GetTickCount() - dwTick > uTimeout * 1000)
		{
			data.tcp.flags = TCP_RST;
			data.tcp.tcpoffset = ((5 + 0 / 4)) << 4;
			data.tcp.tcpchksum = 0;
			data.tcp.tcpchksum = ~tcp_chksum((UCHAR *) &data.tcp, (UCHAR *) &dwUnicastAddr, (UCHAR *) &ipAddress, sizeof (TCP_HEADER));

			pcap_sendpacket(pcap_dev, (PUCHAR) &data, sizeof (data) - sizeof (data.opt));

			return PORT_STATUS_CLOSED;
		}
	}

	if (PortUnfilteredIsSet(ntohs(wPort)))
		return PORT_STATUS_CLOSED_UNFILTERED;

	return PORT_STATUS_OPEN;
}

void SYNReset(void *buff)
{
	FULL_TCP_PACKET data;
	FULL_TCP_PACKET *packet = (FULL_TCP_PACKET *) buff;

	memset(&data, 0, sizeof (data));

	memcpy(data.eth.et_dest, packet->eth.et_src, 6);
	memcpy(data.eth.et_src, packet->eth.et_dest, 6);
	data.eth.et_protlen = packet->eth.et_protlen;

	data.ip.ip_hl_v  = 0x45;
	data.ip.ip_tos   = 0;
	data.ip.ip_len   = htons(sizeof (IP_HEADER) + sizeof (TCP_HEADER));
	data.ip.ip_id    = htons(0x1000 + rand() % 0xefff);
	data.ip.ip_off   = htons(0x4000);
	data.ip.ip_ttl   = 128;
	data.ip.ip_p     = IPPROTO_TCP;
	data.ip.ip_sum   = 0;
	data.ip.ip_src   = packet->ip.ip_dst;
	data.ip.ip_dst   = packet->ip.ip_src;
	data.ip.ip_sum   = ~ip_chksum((UCHAR *) &data.ip, sizeof (IP_HEADER));

	data.tcp.srcport = packet->tcp.destport;
	data.tcp.destport = packet->tcp.srcport;
	data.tcp.seqno = packet->tcp.ackno;
	data.tcp.ackno = htonl(ntohl(packet->tcp.seqno) + 1);
	data.tcp.tcpoffset = ((5 + 0 / 4)) << 4;;
	data.tcp.flags = TCP_RST;
	data.tcp.wnd = 0;
	data.tcp.urgp = 0;

	data.tcp.tcpchksum = ~tcp_chksum((UCHAR *) &data.tcp, (UCHAR *) &data.ip.ip_src, (UCHAR *) &data.ip.ip_dst, sizeof (TCP_HEADER));

	pcap_sendpacket(pcap_dev, (PUCHAR) &data, sizeof (data) - sizeof (data.opt));
}

static USHORT chksum(USHORT sum, const UCHAR *data, USHORT len)
{
	USHORT t;
	const UCHAR *dataptr;
	const UCHAR *last_byte;

	dataptr = data;
	last_byte = data + len - 1;

	while(dataptr < last_byte) {	/* At least two more bytes */
		t = (dataptr[0] << 8) + dataptr[1];
		sum += t;
		if(sum < t) {
			sum++;		/* carry */
		}
		dataptr += 2;
	}

	if(dataptr == last_byte) {
		t = (dataptr[0] << 8) + 0;
		sum += t;
		if(sum < t) {
			sum++;		/* carry */
		}
	}

	/* Return sum in host byte order. */
	return sum;
}

static USHORT ip_chksum(UCHAR *sdata, USHORT len)
{
	USHORT sum;

	sum = chksum(0, sdata, len);
	return (sum == 0) ? 0xffff : htons(sum);
}

static USHORT tcp_chksum(UCHAR *tcp_buf, UCHAR *src_ip, UCHAR *dst_ip, USHORT len)
{
	USHORT upper_layer_len;
	USHORT sum;

	upper_layer_len = len;

	sum = upper_layer_len + IPPROTO_TCP;

	sum = chksum(sum, src_ip, 4);
	sum = chksum(sum, dst_ip, 4);

	sum = chksum(sum, tcp_buf, upper_layer_len);

	return (sum == 0) ? 0xffff : htons(sum);
}