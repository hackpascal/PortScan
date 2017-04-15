#pragma once

typedef struct _PORT_SERVICE
{
	WORD wPort;
	const char *name;
	const char *description;
} PORT_SERVICE, *PPORT_SERVICE;

extern PORT_SERVICE g_pPortServices[];
extern const int g_nNumOfServices;

const char *GetPortService(WORD wPort);
