"""The borrowed loading path: Zeek and Palo Alto sessions land in one table, and a session both
sensors saw is counted once."""
import os
import tempfile
import unittest

from pentaiwatch import netmap, scanners
from pentaiwatch.errors import UserError
from pentaiwatch.load import load
from pentaiwatch.schema import START_ZEEK_TS
from tests import kit

T0 = 1_790_000_000.0          # a whole second, so Palo Alto's one-second times line up
SRC, HOST = "203.0.113.10", "10.10.1.20"


def sessions():
    return [kit.session(T0, SRC, HOST, 443, "SF"), kit.session(T0 + 5, SRC, HOST, 22, "S0"),
            kit.session(T0 + 9, SRC, HOST, 8443, "REJ"), kit.session(T0 + 12, SRC, HOST, 443, "RSTR")]


class LoadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def path(self, name):
        return os.path.join(self.dir, name)

    def load(self, *paths, **kw):
        ds = load(list(paths), workdir=self.dir, **kw)
        self.addCleanup(ds.close)
        return ds

    def test_zeek_sessions_keep_state_and_start_method(self):
        ds = self.load(kit.write_zeek_conn(self.path("conn.log"), sessions()))
        flows = list(ds.flows)
        self.assertEqual([f.state for f in flows], ["SF", "S0", "REJ", "RSTR"])
        self.assertEqual({f.start_method for f in flows}, {START_ZEEK_TS})
        self.assertEqual([f.pkts_in for f in flows], [7, 0, 1, 2])
        self.assertEqual(ds.sensors, ["zeek"])
        self.assertEqual((ds.duplicate_flows, ds.cross_sensor_duplicates), (0, 0))

    def test_gzip_log_reads_the_same(self):
        plain = self.load(kit.write_zeek_conn(self.path("conn.log"), sessions()))
        gz = self.load(kit.write_zeek_conn(self.path("conn.2026.log.gz"), sessions()))
        self.assertEqual([f.key() for f in plain.flows], [f.key() for f in gz.flows])

    def test_paloalto_sessions_load(self):
        ds = self.load(kit.write_paloalto(self.path("traffic.csv"), sessions()))
        flows = list(ds.flows)
        self.assertEqual([f.action for f in flows], ["allow", "deny", "allow", "allow"])
        self.assertEqual([f.established for f in flows], [True, False, False, False])
        self.assertEqual(ds.sensors, ["paloalto"])

    def test_session_seen_by_both_sensors_counts_once(self):
        ds = self.load(kit.write_zeek_conn(self.path("conn.log"), sessions()),
                       kit.write_paloalto(self.path("traffic.csv"), sessions()))
        self.assertEqual(len(ds.flows), 4)
        # same instant and action: an exact duplicate; otherwise matched across sensors
        self.assertEqual(ds.duplicate_flows + ds.cross_sensor_duplicates, 4)
        self.assertEqual(ds.sensors, ["paloalto", "zeek"])
        # the firewall's record is the one kept (it knows the policy action)
        self.assertEqual([f.action for f in ds.flows], ["allow", "deny", "allow", "allow"])

    def test_two_zeek_taps_count_a_session_once(self):
        ds = self.load(kit.write_zeek_conn(self.path("conn.log"), sessions()),
                       kit.write_zeek_conn(self.path("tap_b_conn.log"), sessions()))
        self.assertEqual(len(ds.flows), 4)

    def test_other_files_are_left_out_and_listed(self):
        with open(self.path("notes.txt"), "w") as fh:
            fh.write("not a log\n")
        ds = self.load(self.path("notes.txt"), kit.write_zeek_conn(self.path("conn.log"), sessions()))
        self.assertEqual(len(ds.flows), 4)
        self.assertIn("left out", ds.stats[0].notes[0])


class ListFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, text):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w") as fh:
            fh.write(text)
        return p

    def test_network_map(self):
        entries = netmap.read(self.write("network_map.csv", "cidr,name,type\n10.10.0.0/16,HQ,on-prem\n"
                                                             "10.10.1.0/24,DMZ,on-prem\n"))
        nm = netmap.NetMap(entries)
        self.assertEqual(nm.name("10.10.1.20"), "DMZ")
        self.assertEqual(nm.name("10.10.9.9"), "HQ")
        self.assertIsNone(nm.index("203.0.113.10"))

    def test_network_map_bad_range_names_the_line(self):
        with self.assertRaisesRegex(UserError, "line 2"):
            netmap.read(self.write("network_map.csv", "cidr,name\nnot-a-range,HQ\n"))

    def test_known_scanners(self):
        known = scanners.Known(scanners.read(self.write(
            "known_scanners.csv", "address,name\n198.51.100.0/28,Surface monitor\n")))
        self.assertEqual(known.label("198.51.100.7"), "Surface monitor")
        self.assertIsNone(known.label("203.0.113.10"))


if __name__ == "__main__":
    unittest.main()
