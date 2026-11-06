#define INITGUID
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <initguid.h>
#include <stdint.h>
#include <stdio.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "ws2_32.lib")

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

// {9DDE7F58-D36B-4D04-9AC1-139945E678F6}
DEFINE_GUID(
    AEGIS_WFP_SUBLAYER,
    0x9dde7f58,
    0xd36b,
    0x4d04,
    0x9a, 0xc1, 0x13, 0x99, 0x45, 0xe6, 0x78, 0xf6);

// {69A35811-2C7F-4EF8-AF4E-0C83B3750848}
DEFINE_GUID(
    AEGIS_WFP_FILTER,
    0x69a35811,
    0x2c7f,
    0x4ef8,
    0xaf, 0x4e, 0x0c, 0x83, 0xb3, 0x75, 0x08, 0x48);

// {38F19AB0-84F4-41B7-8551-489668067BA4}
DEFINE_GUID(
    AEGIS_WFP_PROVIDER_CONTEXT,
    0x38f19ab0,
    0x84f4,
    0x41b7,
    0x85, 0x51, 0x48, 0x96, 0x68, 0x06, 0x7b, 0xa4);

typedef struct AEGIS_WFP_RUNTIME_CONFIG {
  UINT32 RemoteIpv4HostOrder;
  UINT16 RemotePortHostOrder;
  UINT16 RedirectPortHostOrder;
  UINT64 RedirectTargetPid;
  UINT64 MatchProcessId;
  BOOLEAN Enabled;
} AEGIS_WFP_RUNTIME_CONFIG;

#define IOCTL_AEGIS_WFP_GET_LOGS \
  CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AEGIS_WFP_CLEAR_LOGS \
  CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AEGIS_WFP_SET_CONFIG \
  CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)

static void print_error(const char* op, DWORD status) {
  fprintf(stderr, "%s failed: 0x%08lx (%lu)\n", op, status, status);
}

static DWORD open_engine(HANDLE* engine) {
  return FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, engine);
}

static DWORD delete_state(void) {
  HANDLE engine = NULL;
  DWORD status = open_engine(&engine);
  HANDLE filters = NULL;
  HANDLE contexts = NULL;
  FWPM_FILTER_ENUM_TEMPLATE0 filter_template;
  FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0 context_template;
  if (status != ERROR_SUCCESS) {
    return status;
  }
  status = FwpmTransactionBegin0(engine, 0);
  if (status != ERROR_SUCCESS) goto done;
  ZeroMemory(&filter_template, sizeof(filter_template));
  filter_template.providerKey = (GUID*)&AEGIS_WFP_PROVIDER;
  filter_template.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
  filter_template.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
  status = FwpmFilterCreateEnumHandle0(engine, &filter_template, &filters);
  if (status != ERROR_SUCCESS) goto abort;
  for (;;) {
    FWPM_FILTER0** entries = NULL;
    UINT32 count = 0;
    UINT32 i;
    status = FwpmFilterEnum0(engine, filters, 256, &entries, &count);
    if (status != ERROR_SUCCESS) goto abort;
    for (i = 0; i < count; ++i) {
      status = FwpmFilterDeleteById0(engine, entries[i]->filterId);
      if (status != ERROR_SUCCESS) break;
    }
    FwpmFreeMemory0((void**)&entries);
    if (status != ERROR_SUCCESS) goto abort;
    if (count == 0) break;
  }
  FwpmFilterDestroyEnumHandle0(engine, filters);
  filters = NULL;
  ZeroMemory(&context_template, sizeof(context_template));
  context_template.providerKey = (GUID*)&AEGIS_WFP_PROVIDER;
  context_template.providerContextType = FWPM_GENERAL_CONTEXT;
  status = FwpmProviderContextCreateEnumHandle0(engine, &context_template, &contexts);
  if (status != ERROR_SUCCESS) goto abort;
  for (;;) {
    FWPM_PROVIDER_CONTEXT0** entries = NULL;
    UINT32 count = 0;
    UINT32 i;
    status = FwpmProviderContextEnum0(engine, contexts, 256, &entries, &count);
    if (status != ERROR_SUCCESS) goto abort;
    for (i = 0; i < count; ++i) {
      status = FwpmProviderContextDeleteByKey0(engine, &entries[i]->providerContextKey);
      if (status != ERROR_SUCCESS) break;
    }
    FwpmFreeMemory0((void**)&entries);
    if (status != ERROR_SUCCESS) goto abort;
    if (count == 0) break;
  }
  FwpmProviderContextDestroyEnumHandle0(engine, contexts);
  contexts = NULL;
  status = FwpmCalloutDeleteByKey0(engine, &AEGIS_WFP_CALLOUT_ALE_CONNECT_REDIRECT_V4);
  if (status != ERROR_SUCCESS && status != FWP_E_CALLOUT_NOT_FOUND) goto abort;
  status = FwpmSubLayerDeleteByKey0(engine, &AEGIS_WFP_SUBLAYER);
  if (status != ERROR_SUCCESS && status != FWP_E_SUBLAYER_NOT_FOUND) goto abort;
  status = FwpmProviderDeleteByKey0(engine, &AEGIS_WFP_PROVIDER);
  if (status != ERROR_SUCCESS && status != FWP_E_PROVIDER_NOT_FOUND) goto abort;
  status = FwpmTransactionCommit0(engine);
  goto done;
abort:
  if (filters != NULL) FwpmFilterDestroyEnumHandle0(engine, filters);
  if (contexts != NULL) FwpmProviderContextDestroyEnumHandle0(engine, contexts);
  FwpmTransactionAbort0(engine);
done:
  FwpmEngineClose0(engine);
  return status;
}

static DWORD dump_driver_logs(const char* path) {
  HANDLE device;
  HANDLE file;
  DWORD bytes = 0;
  DWORD written = 0;
  BYTE buffer[64 * 1024];

  device = CreateFileA(
      "\\\\.\\AegisWfp",
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL);
  if (device == INVALID_HANDLE_VALUE) {
    return GetLastError();
  }

  ZeroMemory(buffer, sizeof(buffer));
  if (!DeviceIoControl(
          device,
          IOCTL_AEGIS_WFP_GET_LOGS,
          NULL,
          0,
          buffer,
          sizeof(buffer),
          &bytes,
          NULL)) {
    DWORD status = GetLastError();
    CloseHandle(device);
    return status;
  }

  file = CreateFileA(
      path,
      GENERIC_WRITE,
      0,
      NULL,
      CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL);
  if (file == INVALID_HANDLE_VALUE) {
    DWORD status = GetLastError();
    CloseHandle(device);
    return status;
  }

  if (bytes > 0 &&
      !WriteFile(file, buffer, bytes, &written, NULL)) {
    DWORD status = GetLastError();
    CloseHandle(file);
    CloseHandle(device);
    return status;
  }

  CloseHandle(file);
  CloseHandle(device);
  return ERROR_SUCCESS;
}

static DWORD clear_driver_logs(void) {
  HANDLE device;
  DWORD bytes = 0;

  device = CreateFileA(
      "\\\\.\\AegisWfp",
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL);
  if (device == INVALID_HANDLE_VALUE) {
    return GetLastError();
  }

  if (!DeviceIoControl(
          device,
          IOCTL_AEGIS_WFP_CLEAR_LOGS,
          NULL,
          0,
          NULL,
          0,
          &bytes,
          NULL)) {
    DWORD status = GetLastError();
    CloseHandle(device);
    return status;
  }

  CloseHandle(device);
  return ERROR_SUCCESS;
}

static DWORD check_driver_api(void) {
  HANDLE device;
  DWORD bytes = 0;
  UINT32 version = 0;

  device = CreateFileA(
      "\\\\.\\AegisWfp",
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL);
  if (device == INVALID_HANDLE_VALUE) {
    return GetLastError();
  }

  if (!DeviceIoControl(
          device,
          CTL_CODE(FILE_DEVICE_NETWORK, 0x804, METHOD_BUFFERED, FILE_READ_DATA),
          NULL,
          0,
          &version,
          sizeof(version),
          &bytes,
          NULL)) {
    DWORD status = GetLastError();
    CloseHandle(device);
    return status;
  }

  CloseHandle(device);
  if (bytes != sizeof(version) || version != 2) return ERROR_REVISION_MISMATCH;
  return ERROR_SUCCESS;
}

static DWORD add_state(
    const char* remote_ip,
    UINT16 remote_port,
    UINT16 redirect_port,
    UINT64 redirect_pid,
    UINT64 match_pid,
    const char* app_path) {
  HANDLE engine = NULL;
  DWORD status;
  UINT32 remote_host_order = 0;
  IN_ADDR parsed;
  WCHAR app_path_w[MAX_PATH * 2];
  FWP_BYTE_BLOB* app_id = NULL;
  FWPM_PROVIDER0 provider;
  FWPM_SUBLAYER0 sublayer;
  FWPM_CALLOUT0 callout;
  FWPM_PROVIDER_CONTEXT0 provider_context;
  FWPM_FILTER0 filter;
  FWPM_FILTER_CONDITION0 conditions[4];
  UINT32 condition_count = 3;
  FWP_BYTE_BLOB context_blob;
  AEGIS_WFP_RUNTIME_CONFIG config;
  GUID context_key;
  GUID filter_key;

  if (remote_port == 0 || redirect_port == 0 || redirect_pid == 0 || redirect_pid > MAXDWORD) {
    return ERROR_INVALID_PARAMETER;
  }
  status = UuidCreate(&context_key);
  if (status != RPC_S_OK && status != RPC_S_UUID_LOCAL_ONLY) return status;
  status = UuidCreate(&filter_key);
  if (status != RPC_S_OK && status != RPC_S_UUID_LOCAL_ONLY) return status;

  if (InetPtonA(AF_INET, remote_ip, &parsed) != 1) {
    fprintf(stderr, "invalid IPv4 address: %s\n", remote_ip);
    return ERROR_INVALID_PARAMETER;
  }
  remote_host_order = ntohl(parsed.S_un.S_addr);
  if ((remote_host_order & 0xff000000UL) == 0x7f000000UL || remote_host_order == 0 ||
      (remote_host_order & 0xf0000000UL) == 0xe0000000UL || remote_host_order == MAXDWORD) {
    return ERROR_INVALID_PARAMETER;
  }
  status = check_driver_api();
  if (status != ERROR_SUCCESS) return status;

  status = open_engine(&engine);
  if (status != ERROR_SUCCESS) {
    return status;
  }

  status = FwpmTransactionBegin0(engine, 0);
  if (status != ERROR_SUCCESS) {
    FwpmEngineClose0(engine);
    return status;
  }

  ZeroMemory(&provider, sizeof(provider));
  provider.providerKey = AEGIS_WFP_PROVIDER;
  provider.displayData.name = L"AEGIS WFP proof provider";
  provider.displayData.description = L"AEGIS-owned minimal ALE connect redirect proof";
  status = FwpmProviderAdd0(engine, &provider, NULL);
  if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) {
    goto abort;
  }

  ZeroMemory(&sublayer, sizeof(sublayer));
  sublayer.subLayerKey = AEGIS_WFP_SUBLAYER;
  sublayer.providerKey = (GUID*)&AEGIS_WFP_PROVIDER;
  sublayer.displayData.name = L"AEGIS WFP proof sublayer";
  sublayer.displayData.description = L"AEGIS controlled proof sublayer";
  sublayer.weight = 0x7000;
  status = FwpmSubLayerAdd0(engine, &sublayer, NULL);
  if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) {
    goto abort;
  }

  ZeroMemory(&callout, sizeof(callout));
  callout.calloutKey = AEGIS_WFP_CALLOUT_ALE_CONNECT_REDIRECT_V4;
  callout.providerKey = (GUID*)&AEGIS_WFP_PROVIDER;
  callout.displayData.name = L"AEGIS ALE connect redirect v4 callout";
  callout.displayData.description = L"AEGIS minimal proof callout";
  callout.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
  status = FwpmCalloutAdd0(engine, &callout, NULL, NULL);
  if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) {
    goto abort;
  }

  ZeroMemory(&config, sizeof(config));
  config.RemoteIpv4HostOrder = remote_host_order;
  config.RemotePortHostOrder = remote_port;
  config.RedirectPortHostOrder = redirect_port;
  config.RedirectTargetPid = redirect_pid;
  config.MatchProcessId = match_pid;
  config.Enabled = TRUE;

  context_blob.size = sizeof(config);
  context_blob.data = (UINT8*)&config;

  ZeroMemory(&provider_context, sizeof(provider_context));
  provider_context.providerContextKey = context_key;
  provider_context.providerKey = (GUID*)&AEGIS_WFP_PROVIDER;
  provider_context.displayData.name = L"AEGIS WFP proof runtime config";
  provider_context.type = FWPM_GENERAL_CONTEXT;
  provider_context.dataBuffer = &context_blob;
  status = FwpmProviderContextAdd0(engine, &provider_context, NULL, NULL);
  if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) {
    goto abort;
  }

  ZeroMemory(conditions, sizeof(conditions));
  conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
  conditions[0].matchType = FWP_MATCH_EQUAL;
  conditions[0].conditionValue.type = FWP_UINT32;
  conditions[0].conditionValue.uint32 = remote_host_order;

  conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
  conditions[1].matchType = FWP_MATCH_EQUAL;
  conditions[1].conditionValue.type = FWP_UINT16;
  conditions[1].conditionValue.uint16 = remote_port;

  conditions[2].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
  conditions[2].matchType = FWP_MATCH_EQUAL;
  conditions[2].conditionValue.type = FWP_UINT8;
  conditions[2].conditionValue.uint8 = IPPROTO_TCP;

  if (app_path != NULL && app_path[0] != '\0') {
    int chars = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        app_path,
        -1,
        app_path_w,
        ARRAYSIZE(app_path_w));
    if (chars == 0) {
      chars = MultiByteToWideChar(
          CP_ACP,
          0,
          app_path,
          -1,
          app_path_w,
          ARRAYSIZE(app_path_w));
    }
    if (chars == 0) {
      status = GetLastError();
      goto abort;
    }

    status = FwpmGetAppIdFromFileName0(app_path_w, &app_id);
    if (status != ERROR_SUCCESS) {
      goto abort;
    }

    conditions[3].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[3].matchType = FWP_MATCH_EQUAL;
    conditions[3].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    conditions[3].conditionValue.byteBlob = app_id;
    condition_count = 4;
  }

  ZeroMemory(&filter, sizeof(filter));
  filter.filterKey = filter_key;
  filter.flags = FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT;
  filter.providerKey = (GUID*)&AEGIS_WFP_PROVIDER;
  filter.displayData.name = L"AEGIS WFP proof controlled redirect filter";
  filter.displayData.description = L"Matches one IPv4 TCP target only";
  filter.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
  filter.subLayerKey = AEGIS_WFP_SUBLAYER;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = 0xF;
  filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
  filter.action.calloutKey = AEGIS_WFP_CALLOUT_ALE_CONNECT_REDIRECT_V4;
  filter.providerContextKey = context_key;
  filter.numFilterConditions = condition_count;
  filter.filterCondition = conditions;

  status = FwpmFilterAdd0(engine, &filter, NULL, NULL);
  if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) {
    goto abort;
  }

  status = FwpmTransactionCommit0(engine);
  FwpmEngineClose0(engine);
  if (app_id != NULL) {
    FwpmFreeMemory0((void**)&app_id);
  }
  return status;

abort:
  FwpmTransactionAbort0(engine);
  FwpmEngineClose0(engine);
  if (app_id != NULL) {
    FwpmFreeMemory0((void**)&app_id);
  }
  return status;
}

static void usage(void) {
  printf("aegis-wfpctl install <remote-ip> <remote-port> <redirect-port> <redirect-pid> [match-pid] [app-path]\n");
  printf("aegis-wfpctl cleanup\n");
  printf("aegis-wfpctl logs <path>\n");
  printf("aegis-wfpctl clear-logs\n");
}

static int decimal_value(const char* text, UINT64 max_value, UINT64* out) {
  UINT64 value = 0;
  if (text == NULL || *text == '\0') return 0;
  for (; *text != '\0'; ++text) {
    UINT64 digit;
    if (*text < '0' || *text > '9') return 0;
    digit = (UINT64)(*text - '0');
    if (value > (max_value - digit) / 10) return 0;
    value = value * 10 + digit;
  }
  *out = value;
  return 1;
}

int main(int argc, char** argv) {
  DWORD status;

  if (argc < 2) {
    usage();
    return 2;
  }

  if (_stricmp(argv[1], "cleanup") == 0) {
    status = delete_state();
    if (status != ERROR_SUCCESS) {
      print_error("cleanup", status);
      return 1;
    }
    printf("AEGIS WFP state removed\n");
    return 0;
  }

  if (_stricmp(argv[1], "logs") == 0) {
    if (argc != 3) {
      usage();
      return 2;
    }
    status = dump_driver_logs(argv[2]);
    if (status != ERROR_SUCCESS) {
      print_error("logs", status);
      return 1;
    }
    printf("AEGIS WFP driver logs written to %s\n", argv[2]);
    return 0;
  }

  if (_stricmp(argv[1], "clear-logs") == 0) {
    status = clear_driver_logs();
    if (status != ERROR_SUCCESS) {
      print_error("clear-logs", status);
      return 1;
    }
    printf("AEGIS WFP driver logs cleared\n");
    return 0;
  }

  if (_stricmp(argv[1], "install") == 0) {
    UINT64 remote_port, redirect_port, redirect_pid, match_pid = 0;
    if (argc != 6 && argc != 7 && argc != 8) {
      usage();
      return 2;
    }

    if (!decimal_value(argv[3], 65535, &remote_port) || remote_port == 0 ||
        !decimal_value(argv[4], 65535, &redirect_port) || redirect_port == 0 ||
        !decimal_value(argv[5], MAXDWORD, &redirect_pid) || redirect_pid == 0 ||
        (argc >= 7 && !decimal_value(argv[6], MAXDWORD, &match_pid))) {
      fprintf(stderr, "ports must be 1..65535; PIDs must be decimal DWORDs and redirect PID nonzero\n");
      return 2;
    }
    status = add_state(
        argv[2],
        (UINT16)remote_port,
        (UINT16)redirect_port,
        redirect_pid,
        match_pid,
        argc == 8 ? argv[7] : NULL);
    if (status != ERROR_SUCCESS) {
      print_error("install", status);
      return 1;
    }
    printf("AEGIS WFP state installed for %s:%s -> 127.0.0.1:%s redirect_pid=%s match_pid=%s app_path=%s\n",
           argv[2],
           argv[3],
           argv[4],
           argv[5],
           argc >= 7 ? argv[6] : "0",
           argc == 8 ? argv[7] : "");
    return 0;
  }

  usage();
  return 2;
}
