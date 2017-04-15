#include "stdafx.h"

#include <bitset>
#include <vector>

#include "ScanWork.h"
#include "Network.h"

pcap_t *pcap_dev = NULL;
DWORD dwTargetAddress = 0;
DWORD dwGatewayAddr = 0;
DWORD dwUnicastAddr = 0;
CHAR pGatewayMACAddr[6];
CHAR pAdapterMACAddr[6];

std::bitset<65536> ports_check, ports_alive, ports_unfiltered;
DWORD ports_seqno[65536];
HANDLE hPortAccessMutex = NULL;

DWORD WINAPI ScanRoutine(LPVOID lpParameter)
{
	PSCAN_THREAD_INFO pScanInfo = (PSCAN_THREAD_INFO) lpParameter;
	CString strStatus;
	int ret;

	for (size_t i = 0; i < pScanInfo->nNumOfPorts; i++)
	{
		if (WaitForSingleObject(pScanInfo->hStopEvent, 0) == WAIT_OBJECT_0)
			break;

		strStatus.Format(_T("线程 %u [#%x] 正在扫描 %u.%u.%u.%u:%u (%u%%)"),
			pScanInfo->nStatusIndex, pScanInfo->dwThreadId,
			pScanInfo->ip4Address & 0xff, (pScanInfo->ip4Address >> 8) & 0xff,
			(pScanInfo->ip4Address >> 16) & 0xff,(pScanInfo->ip4Address >>24) & 0xff,
			pScanInfo->pPorts[i], (i + 1) * 100 / pScanInfo->nNumOfPorts);
		pScanInfo->pfnThreadStatusUpdate(pScanInfo->pScanDlg, pScanInfo->nStatusIndex, strStatus);

		ret = pScanInfo->pfnScanMethod(pScanInfo->ip4Address, htons(pScanInfo->pPorts[i]), pScanInfo->uTimeout);

		if (ret == PORT_STATUS_OPEN)
			pScanInfo->pfnAddPort(pScanInfo->pScanDlg, pScanInfo->pPorts[i], FALSE);
	//	else if (ret == PORT_STATUS_CLOSED_UNFILTERED)
	//		pScanInfo->pfnAddPort(pScanInfo->pScanDlg, pScanInfo->pPorts[i], TRUE);
	}

	strStatus.Format(_T("线程 %u [#%x] 结束"), pScanInfo->nStatusIndex, pScanInfo->dwThreadId);
	pScanInfo->pfnThreadStatusUpdate(pScanInfo->pScanDlg, pScanInfo->nStatusIndex, strStatus);

	pScanInfo->pfnThreadStopNotify(pScanInfo->pScanDlg, pScanInfo->nStatusIndex);

	return 0;
}

static PMIB_IPFORWARDTABLE GetIPRouteTable()
{
	PMIB_IPFORWARDTABLE pIpRouteTable;
	ULONG uSize = 0;

	if (GetIpForwardTable(NULL, &uSize, TRUE) != ERROR_INSUFFICIENT_BUFFER)
		return NULL;

	pIpRouteTable = (PMIB_IPFORWARDTABLE) malloc(uSize);
	if (GetIpForwardTable(pIpRouteTable, &uSize, TRUE) != NO_ERROR)
	{
		free(pIpRouteTable);
		return NULL;
	}

	return pIpRouteTable;
}

static PMIB_IPADDRTABLE GetIPAddrTable()
{
	PMIB_IPADDRTABLE pIpAddrTable;
	ULONG uSize = 0;

	if (GetIpAddrTable(NULL, &uSize, TRUE) != ERROR_INSUFFICIENT_BUFFER)
		return NULL;

	pIpAddrTable = (PMIB_IPADDRTABLE) malloc(uSize);
	if (GetIpAddrTable(pIpAddrTable, &uSize, TRUE) != NO_ERROR)
	{
		free(pIpAddrTable);
		return NULL;
	}

	return pIpAddrTable;
}

static BOOL CheckInterfaceIPAddress(PMIB_IPADDRTABLE pIpAddrTable, DWORD dwForwardIfIndex, DWORD dwAddress)
{
	for (DWORD i = 0; i < pIpAddrTable->dwNumEntries; i++)
	{
		if (pIpAddrTable->table[i].dwIndex == dwForwardIfIndex)
			if (pIpAddrTable->table[i].dwAddr == dwAddress && (pIpAddrTable->table[i].wType & MIB_IPADDR_PRIMARY))
				return TRUE;
	}

	return FALSE;
}

static DWORD FindMetric(PMIB_IPFORWARDTABLE pIpRouteTable, PMIB_IPADDRTABLE pIpAddrTable, DWORD dwAddress)
{
	for (DWORD i = 0; i < pIpRouteTable->dwNumEntries; i++)
	{
		if (pIpRouteTable->table[i].dwForwardDest != INADDR_ANY)
			continue;

		if (CheckInterfaceIPAddress(pIpAddrTable, pIpRouteTable->table[i].dwForwardIfIndex, dwAddress))
			return pIpRouteTable->table[i].dwForwardMetric1;
	}

	return (DWORD) -1;
}

static BOOL GetAdapterIpAddress(const char *name, PDWORD pUnicastAddr, PDWORD pGatewayAddr)
{
	int Family = AF_UNSPEC;
	PIP_ADAPTER_ADDRESSES pAddresses = NULL, pCurrAddresses;
	PIP_ADAPTER_UNICAST_ADDRESS_LH pUnicast = NULL;
	PIP_ADAPTER_GATEWAY_ADDRESS_LH pGateway = NULL;
	ULONG pOutBufLen = 0;
	ULONG uFlags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS;
	sockaddr_in *addr4;

	if (GetAdaptersAddresses(Family, uFlags, NULL, pAddresses, &pOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		
		pAddresses = (PIP_ADAPTER_ADDRESSES)new char[pOutBufLen];
		if (GetAdaptersAddresses(Family, uFlags, NULL, pAddresses, &pOutBufLen) != ERROR_SUCCESS)
		{
			delete [] (char*)pAddresses;
			return false;
		}

		pCurrAddresses = pAddresses;

		while (pCurrAddresses)
		{
			if (!strncmp(pCurrAddresses->AdapterName, name + strlen(name) - strlen(pCurrAddresses->AdapterName), strlen(pCurrAddresses->AdapterName)))
			{
				pUnicast = pCurrAddresses->FirstUnicastAddress;
				while (pUnicast)
				{						
					if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
					{
						addr4 = (sockaddr_in*) pUnicast->Address.lpSockaddr;
						if (pUnicastAddr) *pUnicastAddr = addr4->sin_addr.S_un.S_addr;
					}

					pUnicast = pUnicast->Next;
				}

				pGateway = pCurrAddresses->FirstGatewayAddress;
				while (pGateway)
				{						
					if (pGateway->Address.lpSockaddr->sa_family == AF_INET)
					{
						addr4 = (sockaddr_in*) pGateway->Address.lpSockaddr;
						if (pGatewayAddr) *pGatewayAddr = addr4->sin_addr.S_un.S_addr;
					}

					pGateway = pGateway->Next;
				}

				return TRUE;
			}

			pCurrAddresses = pCurrAddresses->Next;
		}

		delete [] (char*)pAddresses;

		return FALSE;
	}

	return FALSE;
}

BOOL GetAdapterMACAddress(char *name, CHAR *addr)
{
	LPADAPTER lpAdapter = 0;
	PPACKET_OID_DATA pOidData;
	BOOLEAN bStatus;

	lpAdapter = PacketOpenAdapter((PCHAR) name);
	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
		return FALSE;

	pOidData = (PPACKET_OID_DATA) malloc(6 + sizeof(PACKET_OID_DATA));
	if (pOidData == NULL) 
	{
		PacketCloseAdapter(lpAdapter);
		return FALSE;
	}

	pOidData->Oid = OID_802_3_CURRENT_ADDRESS;
	pOidData->Length = 6;
	ZeroMemory(pOidData->Data, 6);

	bStatus = PacketRequest(lpAdapter, FALSE, pOidData);
	PacketCloseAdapter(lpAdapter);

	if (!bStatus)
		return FALSE;

	memcpy(addr, pOidData->Data, 6);

	free(pOidData);

	return TRUE;
}

static HANDLE hDetectThread;
static HANDLE hStopEvent;

static DWORD WINAPI PcapDetectRoutine(LPVOID lpParameter);

BOOL PcapStart()
{
	PMIB_IPFORWARDTABLE pIpRouteTable;
	PMIB_IPADDRTABLE pIpAddrTable;
	char err_text[PCAP_ERRBUF_SIZE];
	pcap_if* pdevices, *pdev;
	char *dev_name = NULL;
	DWORD dwMetric = (DWORD) -1, dwTempMetric;
	DWORD dwAddr, dwGWAddr, dwTempAddr, dwTempGWAddr;
	ULONG uLength;
	DWORD dwThreadId;

	pIpRouteTable = GetIPRouteTable();
	pIpAddrTable = GetIPAddrTable();

	if (pcap_findalldevs(&pdevices, err_text) == -1)
	{
		if (pIpRouteTable)
			free(pIpRouteTable);

		if (pIpAddrTable)
			free(pIpAddrTable);

		return FALSE;
	}

	pdev = pdevices;
	while (pdev)
	{
		GetAdapterIpAddress(pdev->name, &dwTempAddr, &dwTempGWAddr);

		dwTempMetric = FindMetric(pIpRouteTable, pIpAddrTable, dwTempAddr);

		if (dwTempMetric < dwMetric)
		{
			dwAddr = dwTempAddr;
			dwGWAddr = dwTempGWAddr;
			dwMetric = dwTempMetric;
			dev_name = pdev->name;
		}

		pdev = pdev->next;
	}

	if (!dev_name)
	{
		if (pIpRouteTable)
			free(pIpRouteTable);

		if (pIpAddrTable)
			free(pIpAddrTable);

		return FALSE;
	}

	dwGatewayAddr = dwGWAddr;
	dwUnicastAddr = dwAddr;

	GetAdapterMACAddress(dev_name, pAdapterMACAddr);

	uLength = 6;
	SendARP(dwGatewayAddr, INADDR_ANY, pGatewayMACAddr, &uLength);

	pcap_dev = pcap_open(dev_name, 1000, PCAP_OPENFLAG_PROMISCUOUS, 20, NULL, err_text);

	if (pIpRouteTable)
		free(pIpRouteTable);

	if (pIpAddrTable)
		free(pIpAddrTable);

	hPortAccessMutex = CreateMutex(NULL, FALSE, NULL);
	ports_alive.reset();
	ports_check.reset();
	ports_unfiltered.reset();

	hStopEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	hDetectThread = CreateThread(NULL, 0, PcapDetectRoutine, NULL, 0, &dwThreadId);
	CloseHandle(hDetectThread);

	return TRUE;
}

void PcapStop()
{
	SetEvent(hStopEvent);

	if (pcap_dev)
	{
		pcap_close(pcap_dev);
		pcap_dev = NULL;
	}
}

BOOL PortCheckIsSet(WORD wPort, DWORD dwSeqNo)
{
	BOOL bResult;

	WaitForSingleObject(hPortAccessMutex, INFINITE);

	bResult = ports_check.test(wPort) && (ports_seqno[wPort] == dwSeqNo - 1);

	ReleaseMutex(hPortAccessMutex);

	return bResult;
}

BOOL PortAliveIsSet(WORD wPort)
{
	BOOL bResult;

	WaitForSingleObject(hPortAccessMutex, INFINITE);

	bResult = ports_alive.test(wPort) == true;

	ReleaseMutex(hPortAccessMutex);

	return bResult;
}

BOOL PortUnfilteredIsSet(WORD wPort)
{
	BOOL bResult;

	WaitForSingleObject(hPortAccessMutex, INFINITE);

	bResult = ports_unfiltered.test(wPort) == true;

	ReleaseMutex(hPortAccessMutex);

	return bResult;
}

void PortCheckSet(WORD wPort, DWORD dwSeqNo)
{
	WaitForSingleObject(hPortAccessMutex, INFINITE);

	ports_check.set(wPort);
	ports_seqno[wPort] = dwSeqNo;

	ReleaseMutex(hPortAccessMutex);
}

void PortAliveSet(WORD wPort)
{
	WaitForSingleObject(hPortAccessMutex, INFINITE);

	ports_alive.set(wPort);

	ReleaseMutex(hPortAccessMutex);
}

void PortUnfilteredSet(WORD wPort)
{
	WaitForSingleObject(hPortAccessMutex, INFINITE);

	ports_unfiltered.set(wPort) == true;

	ReleaseMutex(hPortAccessMutex);
}

WORD GetNextPort()
{
	static WORD wInternalPort = 55555;
	WORD wPort;

	WaitForSingleObject(hPortAccessMutex, INFINITE);

	wPort = wInternalPort++;

	if (wInternalPort == 65535)
		wInternalPort = 55555;

	ReleaseMutex(hPortAccessMutex);

	return wPort;
}

static DWORD WINAPI PcapDetectRoutine(LPVOID lpParameter)
{
	PFULL_TCP_PACKET packet;
	struct pcap_pkthdr *header;
	int ret;

	while (WaitForSingleObject(hStopEvent, 0) != WAIT_OBJECT_0)
	{
		ret = pcap_next_ex(pcap_dev, &header, (const unsigned char **) &packet);

		if (ret < 0)
			break;

		if (ret == 0)
		{
			Sleep(20);
			continue;
		}

		if (packet->eth.et_protlen != htons(PROT_IP))
			continue;

		if (packet->ip.ip_src != dwTargetAddress || packet->ip.ip_dst != dwUnicastAddr)
			continue;

		if (packet->ip.ip_p != IPPROTO_TCP)
			continue;

		if (!PortCheckIsSet(ntohs(packet->tcp.destport), ntohl(packet->tcp.ackno)))
			continue;

		if (packet->tcp.flags & TCP_RST)
		{
			PortUnfilteredSet(ntohs(packet->tcp.srcport));
			PortAliveSet(ntohs(packet->tcp.srcport));
		}
		else if ((packet->tcp.flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK))
		{
			PortAliveSet(ntohs(packet->tcp.srcport));
			SYNReset(packet);
		}

	}

	CloseHandle(hStopEvent);

	return 0;
}