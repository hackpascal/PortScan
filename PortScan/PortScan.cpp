
// PortScan.cpp : ����Ӧ�ó��������Ϊ��
//

#include "stdafx.h"
#include "PortScan.h"
#include "PortScanDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CPortScanApp

BEGIN_MESSAGE_MAP(CPortScanApp, CWinApp)
	ON_COMMAND(ID_HELP, CWinApp::OnHelp)
END_MESSAGE_MAP()


// CPortScanApp ����

CPortScanApp::CPortScanApp()
{
	WSADATA wsa;

	// TODO: �ڴ˴���ӹ�����룬
	// ��������Ҫ�ĳ�ʼ�������� InitInstance ��

	WSAStartup(MAKEWORD(2, 2), &wsa);
}

CPortScanApp::~CPortScanApp()
{
	WSACleanup();
}


// Ψһ��һ�� CPortScanApp ����

CPortScanApp theApp;


// CPortScanApp ��ʼ��

BOOL CPortScanApp::InitInstance()
{
	// ���һ�������� Windows XP �ϵ�Ӧ�ó����嵥ָ��Ҫ
	// ʹ�� ComCtl32.dll �汾 6 ����߰汾�����ÿ��ӻ���ʽ��
	//����Ҫ InitCommonControlsEx()�����򣬽��޷��������ڡ�
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// ��������Ϊ��������Ҫ��Ӧ�ó�����ʹ�õ�
	// �����ؼ��ࡣ
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();


	AfxEnableControlContainer();

	// ��׼��ʼ��
	// ���δʹ����Щ���ܲ�ϣ����С
	// ���տ�ִ���ļ��Ĵ�С����Ӧ�Ƴ�����
	// ����Ҫ���ض���ʼ������

	CPortScanDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();

	// ���ڶԻ����ѹرգ����Խ����� FALSE �Ա��˳�Ӧ�ó���
	//  ����������Ӧ�ó������Ϣ�á�
	return FALSE;
}

