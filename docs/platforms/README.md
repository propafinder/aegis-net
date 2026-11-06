# Platform responsibilities

| Platform | Guide | Runtime / tool owner |
|---|---|---|
| Linux | [Linux](linux/README.md) | Client ingress/OS routing plus packaging systemd helpers |
| Windows | [Windows](windows/README.md) | Client native tunnel/service plus aegis-winctl |
| macOS | [macOS](macos/README.md) | macos_tunnel worker/parent plus explicit utun lab |
| Android | [Android](android/README.md) | JNI proof surface; accepted product flow absent |

Common relay/authentication logic belongs to core/server rather than being
duplicated per OS. [Component ownership](../architecture/OWNERSHIP.md) explains
that boundary; [operator guides](../operator-guides/README.md) describe profiles.
Parent: [documentation](../README.md).
