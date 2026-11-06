#include "aegis_wfp.h"

static PDEVICE_OBJECT gDeviceObject;
static UINT32 gCalloutId;
static HANDLE gRedirectHandle;
static KSPIN_LOCK gDebugLogLock;
static CHAR gDebugLog[AEGIS_WFP_DEBUG_LOG_BYTES];
static ULONG gDebugLogOffset;
static const UNICODE_STRING AegisDeviceName =
    RTL_CONSTANT_STRING(AEGIS_WFP_DEVICE_NAME);
static const UNICODE_STRING AegisSymbolicName =
    RTL_CONSTANT_STRING(AEGIS_WFP_SYMBOLIC_NAME);

static UINT16 AegisHostToNetwork16(UINT16 value) {
  return RtlUshortByteSwap(value);
}

static UINT16 AegisNetworkToHost16(UINT16 value) {
  return RtlUshortByteSwap(value);
}

static UINT32 AegisNetworkToHost32(UINT32 value) {
  return RtlUlongByteSwap(value);
}

static void AegisFormatIpv4(UINT32 hostOrder, CHAR* buffer, size_t bufferBytes) {
  RtlStringCbPrintfA(
      buffer,
      bufferBytes,
      "%u.%u.%u.%u",
      (hostOrder >> 24) & 0xff,
      (hostOrder >> 16) & 0xff,
      (hostOrder >> 8) & 0xff,
      hostOrder & 0xff);
}

static void AegisDebugLog(const CHAR* format, ...) {
  CHAR line[512];
  size_t length = 0;
  va_list args;
  KIRQL oldIrql;

  va_start(args, format);
  if (!NT_SUCCESS(RtlStringCbVPrintfA(line, sizeof(line), format, args))) {
    RtlStringCbCopyA(line, sizeof(line), "log_format_failed\n");
  }
  va_end(args);

  RtlStringCbLengthA(line, sizeof(line), &length);
  DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "%s", line);

  KeAcquireSpinLock(&gDebugLogLock, &oldIrql);
  if (length + 1 >= AEGIS_WFP_DEBUG_LOG_BYTES) {
    gDebugLogOffset = 0;
  } else if (gDebugLogOffset + length + 1 >= AEGIS_WFP_DEBUG_LOG_BYTES) {
    const CHAR marker[] = "debug_log_wrapped\n";
    RtlCopyMemory(gDebugLog, marker, sizeof(marker) - 1);
    gDebugLogOffset = sizeof(marker) - 1;
  }

  if (gDebugLogOffset + length + 1 < AEGIS_WFP_DEBUG_LOG_BYTES) {
    RtlCopyMemory(gDebugLog + gDebugLogOffset, line, length);
    gDebugLogOffset += (ULONG)length;
    gDebugLog[gDebugLogOffset++] = '\n';
  }
  KeReleaseSpinLock(&gDebugLogLock, oldIrql);
}

static void AegisCompleteIrp(PIRP irp, NTSTATUS status, ULONG_PTR information) {
  irp->IoStatus.Status = status;
  irp->IoStatus.Information = information;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
}

NTSTATUS AegisWfpCreateClose(PDEVICE_OBJECT deviceObject, PIRP irp) {
  UNREFERENCED_PARAMETER(deviceObject);
  AegisCompleteIrp(irp, STATUS_SUCCESS, 0);
  return STATUS_SUCCESS;
}

NTSTATUS AegisWfpDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp) {
  PIO_STACK_LOCATION stack;
  ULONG ioctl;
  NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
  ULONG_PTR information = 0;
  KIRQL oldIrql;

  UNREFERENCED_PARAMETER(deviceObject);

  stack = IoGetCurrentIrpStackLocation(irp);
  ioctl = stack->Parameters.DeviceIoControl.IoControlCode;

  if (ioctl == IOCTL_AEGIS_WFP_GET_LOGS) {
    ULONG outBytes = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG copyBytes;

    KeAcquireSpinLock(&gDebugLogLock, &oldIrql);
    copyBytes = min(outBytes, gDebugLogOffset);
    if (copyBytes > 0) {
      RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, gDebugLog, copyBytes);
    }
    KeReleaseSpinLock(&gDebugLogLock, oldIrql);

    status = STATUS_SUCCESS;
    information = copyBytes;
  } else if (ioctl == IOCTL_AEGIS_WFP_CLEAR_LOGS) {
    KeAcquireSpinLock(&gDebugLogLock, &oldIrql);
    gDebugLogOffset = 0;
    RtlZeroMemory(gDebugLog, sizeof(gDebugLog));
    KeReleaseSpinLock(&gDebugLogLock, oldIrql);
    status = STATUS_SUCCESS;
  } else if (ioctl == CTL_CODE(FILE_DEVICE_NETWORK, 0x804, METHOD_BUFFERED, FILE_READ_DATA)) {
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(UINT32)) {
      status = STATUS_BUFFER_TOO_SMALL;
    } else {
      *(UINT32*)irp->AssociatedIrp.SystemBuffer = 2;
      information = sizeof(UINT32);
      status = STATUS_SUCCESS;
    }
  } else if (ioctl == IOCTL_AEGIS_WFP_SET_CONFIG) {
    // API 2 uses immutable per-filter provider contexts. Old controllers must
    // not receive success for a global policy that is no longer consulted.
    status = STATUS_NOT_SUPPORTED;
  }

  AegisCompleteIrp(irp, status, information);
  return status;
}

static BOOLEAN AegisReadClassifyTuple(
    const FWPS_INCOMING_VALUES* values,
    UINT32* remoteIpv4HostOrder,
    UINT16* remotePortHostOrder,
    UINT8* protocol) {
  if (values->valueCount <= FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT) {
    AegisDebugLog(
        "loop_prevention_reason_if_skipped=tuple_value_count_too_small value_count=%lu layer=%u",
        values->valueCount,
        values->layerId);
    return FALSE;
  }

  if (values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.type != FWP_UINT32 ||
      values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.type != FWP_UINT16 ||
      values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.type != FWP_UINT8) {
    AegisDebugLog(
        "loop_prevention_reason_if_skipped=tuple_type_mismatch remote_addr_type=%u remote_port_type=%u protocol_type=%u",
        values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.type,
        values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.type,
        values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.type);
    return FALSE;
  }

  *remoteIpv4HostOrder =
      values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
  *remotePortHostOrder =
      values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16;
  *protocol =
      values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8;

  return TRUE;
}

static NTSTATUS AegisRedirectConnect(
    const void* classifyContext,
    const FWPS_FILTER* filter,
    FWPS_CLASSIFY_OUT* classifyOut,
    UINT16 redirectPortHostOrder,
    UINT64 redirectTargetPid) {
  UINT64 classifyHandle = 0;
  FWPS_CONNECT_REQUEST* request = NULL;
  NTSTATUS status;
  SOCKADDR_IN* remote;
  SOCKADDR_IN* local;
  SOCKADDR_STORAGE* redirectContext = NULL;
  CHAR originalAddr[32];
  CHAR rewrittenAddr[32];
  UINT32 originalRequestRemoteHostOrder;
  UINT16 originalRequestRemotePortHostOrder;

  status = FwpsAcquireClassifyHandle((void*)classifyContext, 0, &classifyHandle);
  AegisDebugLog("acquire_classify_handle_status=0x%08x classify_handle=%llu", status, classifyHandle);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = FwpsAcquireWritableLayerDataPointer(
      classifyHandle,
      filter->filterId,
      0,
      (PVOID*)&request,
      classifyOut);
  AegisDebugLog(
      "acquired_writable_layer_data status=0x%08x has_request=%u filter_id=%llu",
      status,
      request != NULL ? 1u : 0u,
      filter->filterId);
  if (!NT_SUCCESS(status)) {
    FwpsReleaseClassifyHandle(classifyHandle);
    return status;
  }

  remote = (SOCKADDR_IN*)&request->remoteAddressAndPort;
  originalRequestRemoteHostOrder = AegisNetworkToHost32(remote->sin_addr.S_un.S_addr);
  originalRequestRemotePortHostOrder = AegisNetworkToHost16(remote->sin_port);
  AegisFormatIpv4(originalRequestRemoteHostOrder, originalAddr, sizeof(originalAddr));
  AegisDebugLog(
      "original_remote_addr=%s original_remote_port=%hu sockaddr_family=%hu",
      originalAddr,
      originalRequestRemotePortHostOrder,
      remote->sin_family);

  redirectContext = (SOCKADDR_STORAGE*)ExAllocatePool2(
      POOL_FLAG_NON_PAGED,
      sizeof(SOCKADDR_STORAGE) * 2,
      AEGIS_WFP_TAG);
  if (redirectContext == NULL) {
    AegisDebugLog("loop_prevention_reason_if_skipped=redirect_context_alloc_failed status=0x%08x", STATUS_NO_MEMORY);
    FwpsReleaseClassifyHandle(classifyHandle);
    return STATUS_NO_MEMORY;
  }
  RtlCopyMemory(&redirectContext[0], &request->remoteAddressAndPort, sizeof(SOCKADDR_STORAGE));
  RtlCopyMemory(&redirectContext[1], &request->localAddressAndPort, sizeof(SOCKADDR_STORAGE));

  local = (SOCKADDR_IN*)&request->localAddressAndPort;
  local->sin_family = AF_INET;
  local->sin_addr.S_un.S_addr = AEGIS_WFP_IPV4_LOOPBACK_NBO;
  local->sin_port = 0;

  remote = (SOCKADDR_IN*)&request->remoteAddressAndPort;
  remote->sin_family = AF_INET;
  remote->sin_addr.S_un.S_addr = AEGIS_WFP_IPV4_LOOPBACK_NBO;
  remote->sin_port = AegisHostToNetwork16(redirectPortHostOrder);
  AegisFormatIpv4(AegisNetworkToHost32(remote->sin_addr.S_un.S_addr), rewrittenAddr, sizeof(rewrittenAddr));
  AegisDebugLog(
      "rewritten_remote_addr=%s rewritten_remote_port=%hu local_addr=127.0.0.1 local_port=0",
      rewrittenAddr,
      AegisNetworkToHost16(remote->sin_port));

  if (gRedirectHandle != NULL) {
    request->localRedirectHandle = gRedirectHandle;
  }
  request->localRedirectContext = redirectContext;
  request->localRedirectContextSize = sizeof(SOCKADDR_STORAGE) * 2;
  AegisDebugLog(
      "local_redirect_target_pid=%llu has_local_redirect_handle=%u local_redirect_context_size=%llu",
      redirectTargetPid,
      request->localRedirectHandle != NULL ? 1u : 0u,
      (UINT64)request->localRedirectContextSize);

  if (redirectTargetPid != 0) {
    request->localRedirectTargetPID = (UINT32)redirectTargetPid;
  }

  classifyOut->actionType = FWP_ACTION_PERMIT;
  classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

  FwpsApplyModifiedLayerData(
      classifyHandle,
      request,
      FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS);
  AegisDebugLog(
      "apply_modified_layer_data_status=void_called flags=FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS classify_action=%u classify_rights=0x%08x",
      classifyOut->actionType,
      classifyOut->rights);

  FwpsReleaseClassifyHandle(classifyHandle);
  return STATUS_SUCCESS;
}

void NTAPI AegisWfpClassifyConnectRedirectV4(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut) {
  UINT32 remoteIpv4 = 0;
  UINT16 remotePort = 0;
  UINT8 protocol = 0;
  AEGIS_WFP_RUNTIME_CONFIG config = {0};
  NTSTATUS status;
  UINT64 processId = 0;
  CHAR remoteAddr[32];
  UNREFERENCED_PARAMETER(layerData);
  UNREFERENCED_PARAMETER(flowContext);

  if (classifyOut == NULL || !(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
    return;
  }
  if (inMetaValues != NULL && FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
    processId = inMetaValues->processId;
  }
  // Log presence, never the pointer values. These logs are readable from user
  // mode via IOCTL_AEGIS_WFP_GET_LOGS and have been committed to the repository
  // in the past, so printing kernel virtual addresses here leaked the kernel
  // address-space layout (a KASLR bypass primitive) to anyone who could read them.
  AegisDebugLog(
      "classify_entered layer=%u value_count=%lu rights=0x%08x action=%u process_id=%llu has_classify_context=%u has_filter=%u callout_api=FWPS_CALLOUT3",
      inFixedValues != NULL ? inFixedValues->layerId : 0,
      inFixedValues != NULL ? inFixedValues->valueCount : 0,
      classifyOut != NULL ? classifyOut->rights : 0,
      classifyOut != NULL ? classifyOut->actionType : 0,
      processId,
      classifyContext != NULL ? 1u : 0u,
      filter != NULL ? 1u : 0u);

  if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
    AegisDebugLog("loop_prevention_reason_if_skipped=no_action_write_right rights=0x%08x", classifyOut->rights);
    return;
  }

  classifyOut->actionType = FWP_ACTION_PERMIT;

  // Immutable context belongs to THIS filter. The former global IOCTL config
  // made the last installed target replace every previous target in a list.
  if (filter != NULL && filter->providerContext != NULL &&
      filter->providerContext->type == FWPM_GENERAL_CONTEXT &&
      filter->providerContext->dataBuffer != NULL &&
      filter->providerContext->dataBuffer->size == sizeof(config) &&
      filter->providerContext->dataBuffer->data != NULL) {
    RtlCopyMemory(&config, filter->providerContext->dataBuffer->data, sizeof(config));
  }
  if (!config.Enabled || classifyContext == NULL || filter == NULL ||
      inFixedValues == NULL || inMetaValues == NULL ||
      config.RedirectTargetPid == 0 || config.RedirectTargetPid > MAXULONG ||
      config.RemoteIpv4HostOrder == 0 || config.RemotePortHostOrder == 0 ||
      config.RedirectPortHostOrder == 0) {
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    AegisDebugLog(
        "loop_prevention_reason_if_skipped=disabled_or_missing_context enabled=%u has_classify_context=%u has_filter=%u",
        config.Enabled,
        classifyContext != NULL ? 1u : 0u,
        filter != NULL ? 1u : 0u);
    return;
  }

  if (gRedirectHandle != NULL &&
      FWPS_IS_METADATA_FIELD_PRESENT(
          inMetaValues,
          FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE)) {
    FWPS_CONNECTION_REDIRECT_STATE redirectState =
        FwpsQueryConnectionRedirectState(
            inMetaValues->redirectRecords,
            gRedirectHandle,
            NULL);
    AegisDebugLog("redirect_state=%u", redirectState);
    if (redirectState == FWPS_CONNECTION_REDIRECTED_BY_SELF) {
      AegisDebugLog("loop_prevention_reason_if_skipped=redirected_by_self");
      return;
    }
    if (redirectState == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF) {
      AegisDebugLog("loop_prevention_reason_if_skipped=previously_redirected_by_self");
      return;
    }
  }

  if (!AegisReadClassifyTuple(
          inFixedValues,
          &remoteIpv4,
          &remotePort,
          &protocol)) {
    return;
  }
  AegisFormatIpv4(remoteIpv4, remoteAddr, sizeof(remoteAddr));
  AegisDebugLog(
      "filter_tuple_seen original_remote_addr=%s original_remote_port=%hu protocol=%u configured_remote=%lu configured_port=%hu",
      remoteAddr,
      remotePort,
      protocol,
      config.RemoteIpv4HostOrder,
      config.RemotePortHostOrder);

  if (protocol != IPPROTO_TCP) {
    AegisDebugLog("loop_prevention_reason_if_skipped=non_tcp protocol=%u", protocol);
    return;
  }

  if ((remoteIpv4 & 0xff000000UL) == 0x7f000000UL ||
      processId == config.RedirectTargetPid) {
    AegisDebugLog("loop_prevention_reason_if_skipped=loopback_or_relay remote=%s", remoteAddr);
    return;
  }

  if (config.MatchProcessId != 0 && processId != config.MatchProcessId) {
    AegisDebugLog(
        "loop_prevention_reason_if_skipped=process_mismatch seen_pid=%llu configured_pid=%llu remote=%s:%hu",
        processId,
        config.MatchProcessId,
        remoteAddr,
        remotePort);
    return;
  }

  if (remotePort != config.RemotePortHostOrder) {
    AegisDebugLog(
        "loop_prevention_reason_if_skipped=remote_port_mismatch seen=%hu configured=%hu",
        remotePort,
        config.RemotePortHostOrder);
    return;
  }

  if (config.RemoteIpv4HostOrder != 0 &&
      remoteIpv4 != config.RemoteIpv4HostOrder) {
    AegisDebugLog(
        "loop_prevention_reason_if_skipped=remote_addr_mismatch seen=%s configured=%lu",
        remoteAddr,
        config.RemoteIpv4HostOrder);
    return;
  }
  AegisDebugLog("filter_matched remote=%s:%hu process_id=%llu", remoteAddr, remotePort, processId);

  status = AegisRedirectConnect(
      classifyContext,
      filter,
      classifyOut,
      config.RedirectPortHostOrder,
      config.RedirectTargetPid);

  if (!NT_SUCCESS(status)) {
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
  }

  AegisDebugLog(
      "redirect_complete original=%s:%hu target=127.0.0.1:%hu pid=%llu status=0x%08x classify_action=%u classify_rights=0x%08x",
      remoteAddr,
      remotePort,
      config.RedirectPortHostOrder,
      config.RedirectTargetPid,
      status,
      classifyOut->actionType,
      classifyOut->rights);
}

NTSTATUS NTAPI AegisWfpNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    FWPS_FILTER* filter) {
  UNREFERENCED_PARAMETER(notifyType);
  UNREFERENCED_PARAMETER(filterKey);
  UNREFERENCED_PARAMETER(filter);

  return STATUS_SUCCESS;
}

void NTAPI AegisWfpFlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext) {
  UNREFERENCED_PARAMETER(layerId);
  UNREFERENCED_PARAMETER(calloutId);
  UNREFERENCED_PARAMETER(flowContext);
}

static NTSTATUS AegisWfpRegisterCallout(PDRIVER_OBJECT driverObject) {
  FWPS_CALLOUT callout;
  NTSTATUS status;

  RtlZeroMemory(&callout, sizeof(callout));
  callout.calloutKey = AEGIS_WFP_CALLOUT_ALE_CONNECT_REDIRECT_V4;
  callout.classifyFn = AegisWfpClassifyConnectRedirectV4;
  callout.notifyFn = AegisWfpNotify;
  callout.flowDeleteFn = AegisWfpFlowDelete;

  // Create the device with an explicit SDDL: SYSTEM and Administrators only.
  //
  // The device exposes privileged filter compatibility and diagnostic IOCTLs.
  // Never inherit the I/O manager's permissive default DACL.
  //
  // SDDL_DEVOBJ_SYS_ALL_ADM_ALL grants GENERIC_ALL to SYSTEM and the local
  // Administrators group and nothing to anyone else. Requires <wdmsec.h> and
  // linking wdmsec.lib (see sources/aegis_wfp.vcxproj).
  status = IoCreateDeviceSecure(
      driverObject,
      0,
      (PUNICODE_STRING)&AegisDeviceName,
      FILE_DEVICE_NETWORK,
      FILE_DEVICE_SECURE_OPEN,
      FALSE,
      &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
      NULL,
      &gDeviceObject);
  AegisDebugLog("io_create_device_status=0x%08x", status);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = IoCreateSymbolicLink(
      (PUNICODE_STRING)&AegisSymbolicName,
      (PUNICODE_STRING)&AegisDeviceName);
  AegisDebugLog("io_create_symbolic_link_status=0x%08x", status);
  if (!NT_SUCCESS(status)) {
    IoDeleteDevice(gDeviceObject);
    gDeviceObject = NULL;
    return status;
  }

  status = FwpsRedirectHandleCreate(&AEGIS_WFP_PROVIDER, 0, &gRedirectHandle);
  AegisDebugLog("redirect_handle_created status=0x%08x has_handle=%u", status, gRedirectHandle != NULL ? 1u : 0u);
  if (!NT_SUCCESS(status)) {
    IoDeleteSymbolicLink((PUNICODE_STRING)&AegisSymbolicName);
    IoDeleteDevice(gDeviceObject);
    gDeviceObject = NULL;
    return status;
  }

  status = FwpsCalloutRegister(gDeviceObject, &callout, &gCalloutId);
  AegisDebugLog(
      "callout_register_status=0x%08x callout_id=%lu layer=FWPS_LAYER_ALE_CONNECT_REDIRECT_V4 api=FWPS_CALLOUT3",
      status,
      gCalloutId);
  if (!NT_SUCCESS(status)) {
    FwpsRedirectHandleDestroy(gRedirectHandle);
    gRedirectHandle = NULL;
    IoDeleteSymbolicLink((PUNICODE_STRING)&AegisSymbolicName);
    IoDeleteDevice(gDeviceObject);
    gDeviceObject = NULL;
    return status;
  }

  return STATUS_SUCCESS;
}

void AegisWfpUnload(PDRIVER_OBJECT driverObject) {
  UNREFERENCED_PARAMETER(driverObject);

  if (gCalloutId != 0) {
    AegisDebugLog("callout_unregister id=%lu", gCalloutId);
    FwpsCalloutUnregisterById(gCalloutId);
    gCalloutId = 0;
  }

  if (gRedirectHandle != NULL) {
    AegisDebugLog("redirect_handle_destroy has_handle=%u", gRedirectHandle != NULL ? 1u : 0u);
    FwpsRedirectHandleDestroy(gRedirectHandle);
    gRedirectHandle = NULL;
  }

  IoDeleteSymbolicLink((PUNICODE_STRING)&AegisSymbolicName);

  if (gDeviceObject != NULL) {
    IoDeleteDevice(gDeviceObject);
    gDeviceObject = NULL;
  }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
  NTSTATUS status;

  UNREFERENCED_PARAMETER(registryPath);

  KeInitializeSpinLock(&gDebugLogLock);
  gDebugLogOffset = 0;
  RtlZeroMemory(gDebugLog, sizeof(gDebugLog));

  driverObject->DriverUnload = AegisWfpUnload;
  driverObject->MajorFunction[IRP_MJ_CREATE] = AegisWfpCreateClose;
  driverObject->MajorFunction[IRP_MJ_CLOSE] = AegisWfpCreateClose;
  driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AegisWfpDeviceControl;

  status = AegisWfpRegisterCallout(driverObject);
  AegisDebugLog("driver_entry_status=0x%08x", status);

  return status;
}
