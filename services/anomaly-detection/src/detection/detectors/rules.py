"""Các rule xác định (deterministic) trên hồ sơ cửa sổ. Ngưỡng ở config/detection.yaml, mục `rules`."""
from detection.detectors.base import Finding, WindowDetector, threshold_score
from detection.features import HostWindowFeatures


class RuleDetector(WindowDetector):
    name = "rules"

    def __init__(self, rules_cfg: dict, window_seconds: float):
        self.cfg = rules_cfg
        self.window = window_seconds
        self.checks = [
            check for rule_name, check in (
                ("port_scan", self._port_scan),
                ("host_sweep", self._host_sweep),
                ("syn_flood", self._syn_flood),
                ("brute_force", self._brute_force),
                ("dns_tunneling", self._dns_tunneling),
                ("dga", self._dga),
                ("inbound_scan", self._inbound_scan),
            )
            if rules_cfg.get(rule_name, {}).get("enabled", False)
        ]

    def evaluate(self, f: HostWindowFeatures) -> list[Finding]:
        findings = []
        for check in self.checks:
            finding = check(f, f.metrics, f.context)
            if finding:
                findings.append(finding)
        return findings

    def _port_scan(self, f, m, ctx) -> Finding | None:
        value = m["max_ports_per_dst"]
        score = threshold_score(value, self.cfg["port_scan"]["min_ports_per_target"])
        if not score:
            return None
        target = ctx.get("scan_target")
        return Finding(
            "rule.port_scan", "port_scan", score,
            f"Probed {value} distinct ports on {target} within {self.window:.0f}s",
            {"target": target, "ports": value, "ports_sample": ctx.get("scan_ports_sample")},
        )

    def _host_sweep(self, f, m, ctx) -> Finding | None:
        cfg = self.cfg["host_sweep"]
        tcp_score = threshold_score(m["max_unanswered_dsts_per_port"], cfg["min_unanswered_targets"])
        icmp_score = threshold_score(m["icmp_echo_targets"], cfg["min_icmp_targets"])
        if not (tcp_score or icmp_score):
            return None
        if tcp_score >= icmp_score:
            value, port = m["max_unanswered_dsts_per_port"], ctx.get("sweep_port")
            return Finding(
                "rule.host_sweep", "host_sweep", tcp_score,
                f"Sent unanswered SYN to {value} hosts on port {port} within {self.window:.0f}s",
                {"port": port, "targets": value, "targets_sample": ctx.get("sweep_targets_sample")},
            )
        value = m["icmp_echo_targets"]
        return Finding(
            "rule.host_sweep", "host_sweep", icmp_score,
            f"Sent ICMP echo (ping) to {value} hosts within {self.window:.0f}s",
            {"protocol": "ICMP", "targets": value},
        )

    def _syn_flood(self, f, m, ctx) -> Finding | None:
        cfg = self.cfg["syn_flood"]
        score = threshold_score(m["syn_out"], cfg["min_syn_per_second"] * self.window)
        ratio = m["syn_completion_ratio"]
        if not score or ratio > cfg["max_completion_ratio"]:
            return None
        top = (ctx.get("top_destinations") or [{}])[0].get("ip")
        return Finding(
            "rule.syn_flood", "dos", score,
            f"Sent {m['syn_out']} SYN ({m['syn_out'] / self.window:.0f}/s) with {ratio:.0%} handshake completion",
            {"syn_out": m["syn_out"], "completion_ratio": ratio, "top_destination": top},
        )

    def _brute_force(self, f, m, ctx) -> Finding | None:
        value = m["max_auth_attempts"]
        score = threshold_score(value, self.cfg["brute_force"]["min_attempts"])
        if not score:
            return None
        target = ctx.get("auth_target", {})
        return Finding(
            "rule.brute_force", "brute_force", score,
            f"{value} connection attempts to {target.get('service') or 'port'} "
            f"{target.get('ip')}:{target.get('port')} within {self.window:.0f}s",
            {"attempts": value, **target},
        )

    def _dns_tunneling(self, f, m, ctx) -> Finding | None:
        cfg = self.cfg["dns_tunneling"]
        value = m["dns_top_domain_subdomains"]
        score = threshold_score(value, cfg["min_unique_subdomains"])
        looks_random = (m["dns_top_domain_avg_entropy"] >= cfg["min_avg_entropy"]
                        or m["dns_top_domain_avg_length"] >= cfg["min_avg_length"])
        if not score or not looks_random:
            return None
        domain = ctx.get("dns_top_domain")
        return Finding(
            "rule.dns_tunneling", "dns_tunneling", score,
            f"Queried {value} distinct subdomains of {domain} (avg length "
            f"{m['dns_top_domain_avg_length']:.0f}, entropy {m['dns_top_domain_avg_entropy']:.2f})",
            {"domain": domain, "unique_subdomains": value,
             "avg_length": m["dns_top_domain_avg_length"], "avg_entropy": m["dns_top_domain_avg_entropy"]},
        )

    def _dga(self, f, m, ctx) -> Finding | None:
        cfg = self.cfg["dga"]
        score = threshold_score(m["dns_nxdomain"], cfg["min_nxdomain"])
        ratio = m["dns_nxdomain_ratio"]
        if not score or ratio < cfg["min_nxdomain_ratio"]:
            return None
        return Finding(
            "rule.dga", "dga", score,
            f"{m['dns_nxdomain']} DNS lookups returned NXDOMAIN ({ratio:.0%} of responses)",
            {"nxdomain": m["dns_nxdomain"], "nxdomain_ratio": ratio, "samples": ctx.get("dns_samples")},
        )

    def _inbound_scan(self, f, m, ctx) -> Finding | None:
        value = m["max_ports_probed_by_source"]
        score = threshold_score(value, self.cfg["inbound_scan"]["min_ports_per_source"])
        if not score:
            return None
        source = ctx.get("probe_source")
        return Finding(
            "rule.inbound_scan", "inbound_scan", score,
            f"External host {source} probed {value} ports on this device within {self.window:.0f}s",
            {"source": source, "ports": value},
        )
