#!/usr/bin/env python3
"""Render a bounded, single-node Kubernetes pilot for the existing carrier.

This adapter deliberately cannot advertise replica failover or scale to zero:
the live TLS connection, descriptor and application stream belong to one process.
"""

import argparse
import ipaddress
import json
import re
from pathlib import PurePosixPath


NAME = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\Z")
IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
CONFIG_ROOT = "/etc/aegis-carrier"
POSTGRES_SOCKET_DIRECTORY = "/run/aegis-postgres"


def absolute_clean(value):
    path = PurePosixPath(value)
    if not value.startswith("/") or value == "/" or "//" in value:
        raise ValueError("absolute non-root path required")
    if any(part in (".", "..") for part in value.split("/")):
        raise ValueError("path traversal rejected")
    return str(path)


def render(*, name, namespace, node, host_ip, port, image, config_root,
           uid, socket_directory=None, replicas=1):
    for label in (name, namespace, node):
        if not NAME.fullmatch(label) or len(label) > 63:
            raise ValueError("invalid Kubernetes name")
    if not IMAGE.fullmatch(image):
        raise ValueError("image must be pinned to a sha256 digest")
    ip = ipaddress.ip_address(host_ip)
    if (ip.version != 4 or ip.is_unspecified or ip.is_multicast or
            ip.is_loopback or ip.is_link_local or ip.is_reserved or
            ip in ipaddress.ip_network("0.0.0.0/8")):
        raise ValueError("host IP must be a concrete unicast IPv4 address")
    if not 1 <= port <= 65535 or not 1 <= uid <= 65535:
        raise ValueError("invalid port or service UID")
    if replicas != 1:
        raise ValueError("active carrier state requires exactly one replica")
    config_root = absolute_clean(config_root)
    if config_root != CONFIG_ROOT:
        raise ValueError("private configuration must use dedicated hostPath")
    if socket_directory is not None:
        socket_directory = absolute_clean(socket_directory)
        if socket_directory != POSTGRES_SOCKET_DIRECTORY:
            raise ValueError("PostgreSQL socket must use dedicated hostPath")
        if (socket_directory == config_root or
                socket_directory.startswith(config_root + "/") or
                config_root.startswith(socket_directory + "/")):
            raise ValueError("socket and configuration mounts must be disjoint")
    volumes = [{"name": "private-config", "hostPath": {
        "path": config_root, "type": "Directory"}}]
    mounts = [{"name": "private-config", "mountPath": config_root, "readOnly": True}]
    if socket_directory:
        volumes.append({"name": "postgres-socket", "hostPath": {
            "path": socket_directory, "type": "Directory"}})
        mounts.append({"name": "postgres-socket", "mountPath": socket_directory,
                       "readOnly": True})
    labels = {"app.kubernetes.io/name": "aegis-web-carrier",
              "app.kubernetes.io/instance": name}
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "replicas": 1, "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": {
                "nodeName": node, "hostNetwork": True,
                "dnsPolicy": "ClusterFirstWithHostNet",
                "automountServiceAccountToken": False,
                "terminationGracePeriodSeconds": 15,
                "securityContext": {"runAsUser": uid, "runAsGroup": uid,
                                    "runAsNonRoot": True},
                "containers": [{
                    "name": "carrier", "image": image,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["/usr/local/bin/aegis-server", "carrier", "--config",
                                config_root + "/carrier.toml"],
                    "ports": [{"name": "https", "containerPort": port,
                               "protocol": "TCP"}],
                    "readinessProbe": {"tcpSocket": {"host": host_ip, "port": port},
                                       "periodSeconds": 5, "timeoutSeconds": 2},
                    "securityContext": {"allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": mounts,
                    "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                                  "limits": {"cpu": "1", "memory": "512Mi"}},
                }], "volumes": volumes,
            }},
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("name", "namespace", "node", "host-ip", "image",
                 "config-root"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--socket-directory")
    parser.add_argument("--replicas", type=int, default=1)
    args = vars(parser.parse_args())
    result = render(**{k.replace("-", "_"): v for k, v in args.items()})
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
