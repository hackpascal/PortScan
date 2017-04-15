#pragma once

#define HAVE_REMOTE
#include <pcap/pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#include <errno.h>

typedef int (*SCAN_ROUTINE)(IP4_ADDRESS ipAddress, WORD wPort, UINT uTimeout);
typedef void (*THREAD_STATUS_UPDATE_ROUTINE)(LPVOID pDlg, int nStatusIndex, LPCTSTR lpText);
typedef void (*THREAD_STOP_NOTIFY_ROUTINE)(LPVOID pDlg, int nStatusIndex);
typedef void (*ADD_PORT_ROUTINE)(LPVOID pDlg, WORD wPort, BOOL bClosed);

typedef struct _SCAN_THREAD_INFO
{
	HANDLE hStopEvent;
	DWORD dwThreadId;
	int nStatusIndex;
	LPVOID pScanDlg;
	UINT uTimeout;
	PWORD pPorts;
	size_t nNumOfPorts;
	IP4_ADDRESS ip4Address;
	SCAN_ROUTINE pfnScanMethod;
	THREAD_STATUS_UPDATE_ROUTINE pfnThreadStatusUpdate;
	THREAD_STOP_NOTIFY_ROUTINE pfnThreadStopNotify;
	ADD_PORT_ROUTINE pfnAddPort;
} SCAN_THREAD_INFO, *PSCAN_THREAD_INFO;

extern pcap_t *pcap_dev;
extern DWORD dwTargetAddress;
extern DWORD dwGatewayAddr;
extern DWORD dwUnicastAddr;
extern CHAR pGatewayMACAddr[6];
extern CHAR pAdapterMACAddr[6];

DWORD WINAPI ScanRoutine(LPVOID lpParameter);
BOOL PcapStart();
void PcapStop();

BOOL PortCheckIsSet(WORD wPort, DWORD dwSeqNo);
BOOL PortAliveIsSet(WORD wPort);
void PortCheckSet(WORD wPort, DWORD dwSeqNo);
void PortAliveSet(WORD wPort);
BOOL PortUnfilteredIsSet(WORD wPort);
WORD GetNextPort();