import unittest

from render_k8s_carrier import render


BASE = dict(name="aegis-carrier", namespace="aegis", node="node1",
            host_ip="10.1.2.3", port=8449,
            image="registry.example/aegis@sha256:" + "a" * 64,
            config_root="/etc/aegis-carrier", uid=1200,
            socket_directory="/run/aegis-postgres")


class RenderTests(unittest.TestCase):
    def test_single_node_direct_tls_contract(self):
        pod = render(**BASE)["spec"]
        self.assertEqual(pod["replicas"], 1)
        self.assertEqual(pod["strategy"], {"type": "Recreate"})
        spec = pod["template"]["spec"]
        self.assertEqual(spec["nodeName"], "node1")
        self.assertTrue(spec["hostNetwork"])
        self.assertFalse(spec["automountServiceAccountToken"])
        container = spec["containers"][0]
        self.assertEqual(container["command"], ["/usr/local/bin/aegis-server",
                                                "carrier", "--config",
                                                "/etc/aegis-carrier/carrier.toml"])
        self.assertEqual(container["readinessProbe"]["tcpSocket"],
                         {"host": "10.1.2.3", "port": 8449})
        self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertTrue(all(m["readOnly"] for m in container["volumeMounts"]))
        self.assertEqual(len(spec["volumes"]), 2)
        self.assertNotIn("env", container)

    def test_scale_and_mutable_image_refused(self):
        for change in ({"replicas": 2}, {"replicas": 0},
                       {"image": "registry.example/aegis:latest"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                render(**(BASE | change))

    def test_unsafe_node_addresses_refused(self):
        for change in ({"host_ip": "0.0.0.0"}, {"host_ip": "127.0.0.1"},
                       {"host_ip": "255.255.255.255"},
                       {"host_ip": "169.254.1.2"},
                       {"host_ip": "0.0.0.1"},
                       {"host_ip": "224.0.0.1"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                render(**(BASE | change))

    def test_broad_and_unsafe_host_mounts_refused(self):
        for change in ({"config_root": "/etc/../private"},
                       {"config_root": "/etc"},
                       {"config_root": "/var/run"},
                       {"socket_directory": "/var/run"},
                       {"socket_directory": "/run"},
                       {"socket_directory": "/etc/aegis-carrier/pg"},
                       {"socket_directory": "/run//pg"}, {"uid": 0}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                render(**(BASE | change))


if __name__ == "__main__":
    unittest.main()
