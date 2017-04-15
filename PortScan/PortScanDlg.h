
// PortScanDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"

#include "ScanWork.h"


// CPortScanDlg �Ի���
class CPortScanDlg : public CDialog
{
// ����
public:
	CPortScanDlg(CWnd* pParent = NULL);	// ��׼���캯��
	~CPortScanDlg();

// �Ի�������
	enum { IDD = IDD_PORTSCAN_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��

private:
	HANDLE m_hStopEvent;
	HANDLE m_hInterfaceMutex;
	HANDLE m_hThreads[10];
	SCAN_THREAD_INFO m_pScanInfo[10];
	WORD *m_pPortsToScan;
	size_t m_nNumOfPorts;

	BOOL m_bScanStarted;

	BOOL GeneratePortList();
	BOOL BeginScan();
	void StopScan();
	
	size_t m_nNumOfThreadsLeft;

public:
	void ThreadStatusUpdate(int nStatusIndex, LPCTSTR lpText);
	void ThreadStopNotify(int nStatusIndex);
	void AddPort(WORD wPort, BOOL bClosed);


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnClose();
	BOOL PreTranslateMessage(MSG* pMsg);
	void OnOK();
	DECLARE_MESSAGE_MAP()
public:
	CString m_sHostName;
	CString m_sPorts;
	CEdit m_pPorts;
	UINT m_nNumOfThreads;
	CButton m_pScan;
	int m_nScanType;
	CListCtrl m_pPortList;
	CListBox m_pThreadStatus;
	afx_msg void OnBnClickedButtonScan();
	UINT m_nScanTimeout;
};

typedef CPortScanDlg *PPortScanDlg;
