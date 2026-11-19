"""Pings (ICMP). An unanswered ping is a failed probe whichever log recorded it, an answered one
is an answer, and a host that answers pings is never a service a source narrowed onto."""
import json
import os
import tempfile
import unittest

from pentaiwatch import config
from pentaiwatch.config import Config
from pentaiwatch.detect import detect
from pentaiwatch.errors import UserError
from pentaiwatch.load import load
from tests import kit, sample

SRC = "203.0.113.80"
HOSTS = [f"10.10.3.{i}" for i in range(1, 41)]
ALIVE = {"10.10.3.5", "10.10.3.9"}                 # the two hosts that answer pings
TARGET = ("10.10.3.5", 443)


def ping_sweep_then_narrow() -> list[dict]:
    """Pings 40 hosts a second apart (two answer), then keeps coming back to one web service: 40
    sessions in bursts of five, a second apart, with 25 seconds between bursts (an agent's pace, so
    the source is flagged and its sweep can be read from the finding)."""
    out, t = [], sample.T0 + 600
    for host in HOSTS:
        out.append(kit.ping(t, SRC, host, answered=host in ALIVE))
        t += 1.0
    t += 60
    for i in range(40):
        out.append(kit.session(t, SRC, TARGET[0], TARGET[1], "SF"))
        t += 25.0 if i % 5 == 4 else 1.0
    return out


def port_sweep_then_pings() -> list[dict]:
    """Sweeps 60 closed ports across 3 hosts, then only pings one host, which answers every time:
    20 pings in pairs a second apart, with 25 seconds between pairs."""
    out, t = [], sample.T0 + 600
    for i, host in enumerate(HOSTS[:3]):
        for port in range(8000 + 20 * i, 8020 + 20 * i):
            out.append(kit.session(t, SRC, host, port, "S0"))
            t += 1.0
    t += 60
    for i in range(20):
        out.append(kit.ping(t, SRC, HOSTS[0], answered=True))
        t += 25.0 if i % 2 else 1.0
    return out


def evidence(f) -> tuple:
    return (f.source, f.services_probed, f.hosts_probed, f.ports_probed, f.failed_share, f.services_answered,
            [(s.host, s.port, s.proto, s.sessions) for s in f.services], f.sessions)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.n = 0

    def path(self, name):
        self.n += 1
        folder = os.path.join(self.tmp.name, str(self.n))
        os.makedirs(folder)
        return os.path.join(folder, name)

    def run_on(self, paths, cfg=None):
        cfg = cfg or Config()
        ds = load(paths, workdir=self.tmp.name, skew_seconds=cfg.dedup_skew_seconds,
                  options={"paloalto": cfg.paloalto})
        self.addCleanup(ds.close)
        return ds, detect(ds.flow_con(), cfg)

    def zeek(self, sessions):
        return kit.write_zeek_conn(self.path("conn.log"), sessions)

    def firewall(self, sessions, **kw):
        return kit.write_paloalto(self.path("traffic.csv"), sessions, **kw)


class PingSweepTests(Base):
    def test_unanswered_pings_make_a_sweep_in_a_zeek_log(self):
        _, got = self.run_on([self.zeek(ping_sweep_then_narrow())])
        self.assertEqual([f.source for f in got.findings], [SRC])
        f = got.findings[0]
        # 40 pinged hosts and the web service: 41 services, 38 pings unanswered
        self.assertEqual((f.services_probed, f.hosts_probed, f.ports_probed), (41, 40, 1))
        self.assertEqual(f.failed_share, round(38 / 41, 3))
        self.assertEqual(f.services_answered, 3)
        self.assertEqual([(s.host, s.port, s.proto) for s in f.services], [(*TARGET, "tcp")])

    def test_with_the_setting_off_zeek_pings_are_neither_failed_nor_answered(self):
        cfg = Config()
        cfg.probing.zeek_icmp_by_reply = False
        _, got = self.run_on([self.zeek(ping_sweep_then_narrow())], cfg)
        self.assertEqual((got.findings, got.probing_sources), ([], 0))

    def test_same_ping_sweep_from_zeek_from_palo_alto_and_from_both(self):
        sessions = ping_sweep_then_narrow()
        _, zeek = self.run_on([self.zeek(sessions)])
        want = evidence(zeek.findings[0])
        # whatever a firewall writes in the port columns of a ping: zeros, or the type and code
        for ping_ports in ((0, 0), (8, 0)):
            for packets in (True, False):
                with self.subTest(ping_ports=ping_ports, packets=packets):
                    fw = self.firewall(sessions, packets=packets, ping_ports=ping_ports)
                    _, alone = self.run_on([fw])
                    self.assertEqual([evidence(f) for f in alone.findings], [want])
                    ds, both = self.run_on([self.zeek(sessions), fw])
                    self.assertEqual([evidence(f) for f in both.findings], [want])
                    self.assertEqual(both.findings[0].log_sources, ["paloalto", "zeek"])
                    # every ping and every session counted once
                    self.assertEqual(ds.flow_con().execute("SELECT count(*) FROM flows").fetchone()[0],
                                     len(sessions))

    def test_pings_stopped_by_the_firewall_are_failed_probes_too(self):
        sessions = ping_sweep_then_narrow()
        _, got = self.run_on([self.firewall(sessions, denied=("OTH",))])
        # every ping is denied, so the two hosts that would have answered count as failed as well
        self.assertEqual((got.findings[0].failed_share, got.findings[0].services_answered), (round(40 / 41, 3), 1))

    def test_zeek_log_without_packet_counts_uses_bytes_back(self):
        path = self.path("conn.json")
        with open(path, "w", encoding="utf-8") as fh:
            for s in ping_sweep_then_narrow():
                icmp = s["proto"] == "icmp"
                back = (56 if s.get("answered") else 0) if icmp else 2600
                fh.write(json.dumps({"_path": "conn", "ts": s["ts"], "id.orig_h": s["src"], "id.orig_p": s["sport"],
                                     "id.resp_h": s["dst"], "id.resp_p": s["dport"], "proto": s["proto"],
                                     "conn_state": s["state"], "orig_bytes": 56 if icmp else 420,
                                     "resp_bytes": back}) + "\n")
        _, got = self.run_on([path])
        self.assertEqual([(f.source, f.failed_share) for f in got.findings], [(SRC, round(38 / 41, 3))])


class NarrowingTests(Base):
    def test_a_host_that_answers_pings_is_not_a_service_narrowed_onto(self):
        _, got = self.run_on([self.zeek(port_sweep_then_pings())])
        self.assertEqual(got.probing_sources, 1)          # the port sweep is seen
        # and coming back with pings is not narrowing
        self.assertEqual((got.narrowing_sources, got.findings), (0, []))

    def test_narrowing_protocols_setting_decides_that(self):
        cfg = Config()
        cfg.narrowing.protocols = ["tcp", "udp", "icmp"]
        _, got = self.run_on([self.zeek(port_sweep_then_pings())], cfg)
        self.assertEqual([[(s.host, s.port, s.proto, s.sessions) for s in f.services] for f in got.findings],
                         [[(HOSTS[0], 0, "icmp", 20)]])


class ReaderTests(Base):
    def test_both_readers_store_a_ping_without_ports(self):
        pings = [kit.ping(sample.T0, SRC, HOSTS[0]), kit.ping(sample.T0 + 5, SRC, HOSTS[1], answered=True)]
        for path in (self.zeek(pings), self.firewall(pings, packets=True, ping_ports=(8, 0))):
            with self.subTest(path=os.path.basename(path)):
                ds, _ = self.run_on([path])
                rows = ds.flow_con().execute(
                    "SELECT proto, src_port, dst_port, pkts_in FROM flows ORDER BY seq").fetchall()
                self.assertEqual(rows, [("icmp", 0, 0, 0), ("icmp", 0, 0, 1)])


class SettingsTests(Base):
    def read(self, data):
        path = self.path("pentaiwatch.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return config.read(path)

    def test_settings_file_can_change_both(self):
        cfg = self.read({"probing": {"zeek_icmp_by_reply": False}, "narrowing": {"protocols": ["TCP"]}})
        self.assertEqual((cfg.probing.zeek_icmp_by_reply, cfg.narrowing.protocols), (False, ["tcp"]))

    def test_wrong_values_are_refused(self):
        for data, said in (({"probing": {"zeek_icmp_by_reply": 1}}, "must be true or false"),
                           ({"probing": {"zeek_icmp_by_reply": "yes"}}, "must be true or false"),
                           ({"narrowing": {"protocols": []}}, "narrowing.protocols must list"),
                           ({"narrowing": {"protocols": ["sctp"]}}, "narrowing.protocols must list")):
            with self.subTest(data=data):
                with self.assertRaises(UserError) as caught:
                    self.read(data)
                self.assertIn(said, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
