#pragma once

extern "C" {
#pragma warning(push)
#pragma warning(disable : 4201)
#pragma warning(disable : 4324)

#include <ntifs.h>
#include <ntddk.h>
// IoCreateDeviceSecure + the SDDL_DEVOBJ_* constants (links against wdmsec.lib).
#include <wdmsec.h>
#include <ndis.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include <netioddk.h>
#include <ntintsafe.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <initguid.h>

#pragma warning(pop)
}

#define AEGIS_WFP_DEVICE_NAME L"\\Device\\AegisWfp"
#define AEGIS_WFP_SYMBOLIC_NAME L"\\DosDevices\\AegisWfp"
#define AEGIS_WFP_TAG 'pWgA'
#define AEGIS_WFP_DEBUG_LOG_BYTES (64 * 1024)
#define IOCTL_AEGIS_WFP_GET_LOGS \
  CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AEGIS_WFP_CLEAR_LOGS \
  CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AEGIS_WFP_SET_CONFIG \
  CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)

#define AEGIS_WFP_REMOTE_PORT 19090
#define AEGIS_WFP_REDIRECT_PORT 18080
#define AEGIS_WFP_IPV4_LOOPBACK_NBO 0x0100007fUL

// {74BDE9BD-538C-4D2F-A0C7-F6E6EA1D2814}
DEFINE_GUID(
    AEGIS_WFP_CALLOUT_ALE_CONNECT_REDIRECT_V4,
    0x74bde9bd,
    0x538c,
    0x4d2f,
    0xa0, 0xc7, 0xf6, 0xe6, 0xea, 0x1d, 0x28, 0x14);

// {52758F52-2E3E-4E12-9F3F-A3A7F1A6F201}
DEFINE_GUID(
    AEGIS_WFP_PROVIDER,
    0x52758f52,
    0x2e3e,
    0x4e12,
    0x9f, 0x3f, 0xa3, 0xa7, 0xf1, 0xa6, 0xf2, 0x01);

typedef struct _AEGIS_WFP_RUNTIME_CONFIG {
  UINT32 RemoteIpv4HostOrder;
  UINT16 RemotePortHostOrder;
  UINT16 RedirectPortHostOrder;
  UINT64 RedirectTargetPid;
  UINT64 MatchProcessId;
  BOOLEAN Enabled;
} AEGIS_WFP_RUNTIME_CONFIG;

extern "C" DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD AegisWfpUnload;
DRIVER_DISPATCH AegisWfpCreateClose;
DRIVER_DISPATCH AegisWfpDeviceControl;

void NTAPI AegisWfpClassifyConnectRedirectV4(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut);

NTSTATUS NTAPI AegisWfpNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    FWPS_FILTER* filter);

void NTAPI AegisWfpFlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext);
