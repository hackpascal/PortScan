
// PortScanDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "PortScan.h"
#include "PortScanDlg.h"

#include <bitset>

#include "Network.h"
#include "PortService.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

static void _ThreadStatusUpdate(LPVOID pDlg, int nStatusIndex, LPCTSTR lpText);
static void _ThreadStopNotify(LPVOID pDlg, int nStatusIndex);
static void _AddPort(LPVOID pDlg, WORD wPort, BOOL bClosed);

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CPortScanDlg 对话框



CPortScanDlg::CPortScanDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPortScanDlg::IDD, pParent)
	, m_sHostName(_T("127.0.0.1"))
	, m_sPorts(_T("7,9,13,19,21,22,23,25,53,79,80,81,110,111,119,135,139,143,211,443,445,465,512-514,554,563,585,636,808,990-995,1025,1027,1080,1352,1433,1521,1525,1701,1723,1800,1935,2049,2401,3306,3128,3389,4899,5000,5800,5900,5901,6000-6009,8000-8080,8181,9000,65301"))
	, m_nScanType(0)
	, m_pPortsToScan(NULL)
	, m_nNumOfPorts(0)
	, m_nNumOfThreads(2)
	, m_bScanStarted(FALSE)
	, m_nScanTimeout(2)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

	m_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	m_hInterfaceMutex = CreateMutex(NULL, FALSE, NULL);

	memset(m_hThreads, 0, sizeof (m_hThreads));
}

CPortScanDlg::~CPortScanDlg()
{
	CloseHandle(m_hStopEvent);
	CloseHandle(m_hInterfaceMutex);
}

void CPortScanDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_HOST, m_sHostName);
	DDX_Text(pDX, IDC_PORTS, m_sPorts);
	DDX_Control(pDX, IDC_PORTS, m_pPorts);
	DDX_Control(pDX, IDC_BUTTON_SCAN, m_pScan);
	DDX_Text(pDX, IDC_THREADS, m_nNumOfThreads);
	DDX_Radio(pDX, IDC_RADIO_CONNECT, m_nScanType);
	DDX_Control(pDX, IDC_LIST_PORTS, m_pPortList);
	DDX_Control(pDX, IDC_LIST_STATUS, m_pThreadStatus);
	DDX_Text(pDX, IDC_TIMEOUT, m_nScanTimeout);
}

BEGIN_MESSAGE_MAP(CPortScanDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDC_BUTTON_SCAN, CPortScanDlg::OnBnClickedButtonScan)
END_MESSAGE_MAP()


// CPortScanDlg 消息处理程序

BOOL CPortScanDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	m_pPortList.InsertColumn(0, _T("端口号"), 0, 100);
	m_pPortList.InsertColumn(1, _T("服务"), 0, 250);
	m_pPortList.SetExtendedStyle(LVS_EX_FULLROWSELECT);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CPortScanDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CPortScanDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// 当用户拖动最小化窗口时系统调用此函数取得光标
// 显示。
HCURSOR CPortScanDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CPortScanDlg::OnClose()
{
	if (m_bScanStarted)
		StopScan();

	CDialog::OnClose();
}


void CPortScanDlg::OnOK()
{
	// 空函数，防止回车键关闭对话框
}

BOOL CPortScanDlg::PreTranslateMessage(MSG* pMsg)
{
	if (pMsg->message == WM_KEYDOWN)
	{
		switch (pMsg->wParam)
		{
		case VK_ESCAPE:
			// 屏蔽对 ESC 键的响应，防止 ESC 键关闭对话框
			// 不使用重载 OnCancel 的原因是正常关闭对话框时会调用 OnCancel
			// 空函数重载 OnCancel 会导致无法正常关闭对话框
			return TRUE;
		}
	}

	return CDialog::PreTranslateMessage(pMsg);
}

BOOL CPortScanDlg::BeginScan()
{
	IP4_ADDRESS ip4Address;
	CString strPrompt;
	size_t nPortsLeft, nPortsToScan;
	PWORD pPortsStart;

	UpdateData(1);

	if (!GetHostAddress(m_sHostName, &ip4Address))
	{
		strPrompt.Format(_T("无法解析主机名 %s"), m_sHostName);
		AfxMessageBox(strPrompt, MB_ICONEXCLAMATION);
		return FALSE;
	}

	if (!GeneratePortList())
	{
		return FALSE;
	}

	if (!m_nNumOfThreads || m_nNumOfThreads > 10)
	{
		AfxMessageBox(_T("并发线程数必须介于 1 到 10 之间"), MB_ICONEXCLAMATION);
		return FALSE;
	}

	ResetEvent(m_hStopEvent);

	m_pPortList.DeleteAllItems();
	m_pThreadStatus.ResetContent();

	nPortsLeft = m_nNumOfPorts;
	nPortsToScan = m_nNumOfPorts / m_nNumOfThreads;
	pPortsStart = m_pPortsToScan;

	memset(m_hThreads, 0, sizeof (m_hThreads));
	memset(m_pScanInfo, 0, sizeof (m_pScanInfo));

	m_nNumOfThreadsLeft = m_nNumOfThreads;

	if (m_nScanType == 1)
	{
		if (!PcapStart())
		{
			AfxMessageBox(_T("WinPcap 初始化失败"), MB_ICONERROR);
			return FALSE;
		}
		

		srand((unsigned int) time(NULL));
		dwTargetAddress = ip4Address;
	}

	for (UINT i = 0; i < m_nNumOfThreads; i++)
	{
		m_hThreads[i] = CreateThread(NULL, 0, ScanRoutine, &m_pScanInfo[i], CREATE_SUSPENDED, &m_pScanInfo[i].dwThreadId);
		
		if (!m_hThreads[i])
		{
			strPrompt.Format(_T("创建第 %u 个线程失败"), i + 1);
			AfxMessageBox(strPrompt, MB_ICONERROR);

			break;
		}

		m_pScanInfo[i].nStatusIndex = i;
		m_pScanInfo[i].hStopEvent = m_hStopEvent;
		m_pScanInfo[i].ip4Address = ip4Address;
		m_pScanInfo[i].pScanDlg = this;

		m_pScanInfo[i].nNumOfPorts = nPortsToScan;
		m_pScanInfo[i].pPorts = pPortsStart;

		m_pScanInfo[i].uTimeout = m_nScanTimeout;

		if (i != m_nNumOfThreads - 1)
		{
			nPortsLeft -= nPortsToScan;
			pPortsStart += nPortsToScan;
		}
		else
		{
			m_pScanInfo[i].nNumOfPorts = nPortsLeft;
		}

		m_pScanInfo[i].pfnAddPort = _AddPort;
		m_pScanInfo[i].pfnThreadStatusUpdate = _ThreadStatusUpdate;
		m_pScanInfo[i].pfnThreadStopNotify = _ThreadStopNotify;
		
		if (m_nScanType == 0)
			m_pScanInfo[i].pfnScanMethod = ConnectScan;
		else
			m_pScanInfo[i].pfnScanMethod = SYNScan;

		ResumeThread(m_hThreads[i]);
	}

	return TRUE;
}

void CPortScanDlg::ThreadStopNotify(int nStatusIndex)
{
	if (m_hThreads[nStatusIndex])
	{
		WaitForSingleObject(m_hInterfaceMutex, INFINITE);
		CloseHandle(m_hThreads[nStatusIndex]);
		m_hThreads[nStatusIndex] = 0;
		m_nNumOfThreadsLeft--;
		ReleaseMutex(m_hInterfaceMutex);
	}

	if (!m_nNumOfThreadsLeft)
	{
		m_pScan.EnableWindow(TRUE);
		m_pScan.SetWindowText(_T("开始"));
		m_bScanStarted = FALSE;

		PcapStop();
	}
}

void CPortScanDlg::StopScan()
{
	SetEvent(m_hStopEvent);
}


void CPortScanDlg::OnBnClickedButtonScan()
{
	if (!m_bScanStarted)
	{
		m_pScan.EnableWindow(FALSE);
		if (BeginScan())
		{
			m_pScan.SetWindowText(_T("停止"));
			m_bScanStarted = TRUE;
		}
		m_pScan.EnableWindow(TRUE);
	}
	else
	{
		m_pScan.EnableWindow(FALSE);
		StopScan();
	}
}

BOOL CPortScanDlg::GeneratePortList()
{
	LPTSTR strPorts, p, n;
	std::bitset<65536> ports;
	CString strPrompt;
	unsigned long val, val2;
	size_t len, c;

#define SKIP_BLANK while (*p && ((*p == ' ') || *p == '\t') && (p < strPorts + len)) p++;
#define ADD_SINGLE(_v) ports.set(_v);

	len = m_sPorts.GetLength();
	strPorts = (LPTSTR) calloc(len + 1, sizeof (TCHAR));
	memcpy(strPorts, m_sPorts, len * sizeof (TCHAR));

	p = strPorts;
	SKIP_BLANK;

	do
	{
		if (!isdigit(*p))
			goto _err;

		val = _tcstoul(p, &n, 10);

		if (p == n)
			goto _err;

		if (val > 65535)
			goto _err;

		p = n;
		SKIP_BLANK;

		if (!*p)
		{
			ADD_SINGLE(val);
			break;
		}

		if (*p == '-')
		{
			p++;
			SKIP_BLANK;

			if (!*p)
				goto _err;

			val2 = _tcstoul(p, &n, 10);

			if (p == n)
				goto _err;

			if (val2 > 65535)
				goto _err;

			p = n;

			if (val < val2)
			{
				for (unsigned long i = val; i <= val2; i++)
					ADD_SINGLE(i);
			}
			else if (val2 < val)
			{
				for (unsigned long i = val2; i <= val; i++)
					ADD_SINGLE(i);
			}
			else
			{
				ADD_SINGLE(val);
			}
		}
		else
		{
			ADD_SINGLE(val);
		}

		SKIP_BLANK;

		if (!*p)
			break;

		if (*p != ',')
			goto _err;

		p++;
		SKIP_BLANK;

	} while (*p && (p < strPorts + len));

	if (m_pPortsToScan)
		delete [] m_pPortsToScan;

	m_nNumOfPorts = ports.count();

	m_pPortsToScan = new WORD[m_nNumOfPorts];

	c = 0;

	for (size_t i = 0; i < 65536; i++)
		if (ports.test(i))
			m_pPortsToScan[c++] = (WORD) i;

	free(strPorts);

	return TRUE;

_err:
	strPrompt.Format(_T("端口范围第 %u 字符无效"), p - strPorts);
	AfxMessageBox(strPrompt, MB_ICONEXCLAMATION);

	m_pPorts.SetSel((int) (p - strPorts), (int) (p - strPorts), TRUE);
	m_pPorts.SetFocus();

	free(strPorts);

	return FALSE;

#undef SKIP_BLANK
#undef ADD_SINGLE
}

void CPortScanDlg::ThreadStatusUpdate(int nStatusIndex, LPCTSTR lpText)
{
	WaitForSingleObject(m_hInterfaceMutex, INFINITE);

	m_pThreadStatus.DeleteString(nStatusIndex);
	m_pThreadStatus.InsertString(nStatusIndex, lpText);

	ReleaseMutex(m_hInterfaceMutex);
}

void CPortScanDlg::AddPort(WORD wPort, BOOL bClosed)
{
	int nIndex;
	CString strTemp;

	WaitForSingleObject(m_hInterfaceMutex, INFINITE);

	nIndex = m_pPortList.GetItemCount();

	if (!bClosed)
		strTemp.Format(_T("%u"), wPort);
	else
		strTemp.Format(_T("%u [已关闭]"), wPort);

	m_pPortList.InsertItem(nIndex, strTemp);

	// TODO: 端口服务
	strTemp = GetPortService(wPort);
	m_pPortList.SetItemText(nIndex, 1, strTemp);

	m_pPortList.PostMessage(WM_VSCROLL, SB_BOTTOM, 0);

	ReleaseMutex(m_hInterfaceMutex);
}

static void _ThreadStatusUpdate(LPVOID pDlg, int nStatusIndex, LPCTSTR lpText)
{
	PPortScanDlg pScanDlg = (PPortScanDlg) pDlg;

	pScanDlg->ThreadStatusUpdate(nStatusIndex, lpText);
}

static void _ThreadStopNotify(LPVOID pDlg, int nStatusIndex)
{
	PPortScanDlg pScanDlg = (PPortScanDlg) pDlg;

	pScanDlg->ThreadStopNotify(nStatusIndex);
}

static void _AddPort(LPVOID pDlg, WORD wPort, BOOL bClosed)
{
	PPortScanDlg pScanDlg = (PPortScanDlg) pDlg;

	pScanDlg->AddPort(wPort, bClosed);
}