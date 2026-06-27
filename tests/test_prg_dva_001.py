import base64
import gzip
import hashlib
import io
import os
import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "prg" / "PRG-DVA-001_v0.2.6.py"
SPEC = importlib.util.spec_from_file_location("prg_dva_001", MODULE_PATH)
crm = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(crm)


def file_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class CleanRoomMutatorTests(unittest.TestCase):
    def make_baseline(self, td: Path) -> Path:
        state = {
            "A.txt": crm._entry_record(
                kind="file", data=b"alpha\n", mode=0o644,
                uid=11, gid=12, uname="u", gname="g", mtime=100
            ),
            "B.txt": crm._entry_record(
                kind="file", data=b"beta\n", mode=0o600,
                uid=21, gid=22, uname="u2", gname="g2", mtime=200
            ),
            "sub": crm._entry_record(
                kind="dir", mode=0o755,
                uid=31, gid=32, uname="u3", gname="g3", mtime=300
            ),
            "sub/C.txt": crm._entry_record(
                kind="file", data=b"gamma\n", mode=0o640,
                uid=41, gid=42, uname="u4", gname="g4", mtime=400
            ),
            "OLD.txt": crm._entry_record(
                kind="file", data=b"old\n", mode=0o644,
                uid=51, gid=52, uname="u5", gname="g5", mtime=500
            ),
        }
        path = td / "baseline.tar.gz"
        crm.write_archive(state, path, root_name="system")
        return path

    def write_instruction(self, td: Path, baseline: Path) -> Path:
        instruction = {
            "format": crm.FORMAT,
            "baseline_sha256": crm.sha256_file(baseline),
            "operations": [
                {
                    "op": "replace",
                    "path": "A.txt",
                    "expected_sha256": file_hash(b"alpha\n"),
                    "content_utf8": "ALPHA\n",
                    "mode": 0o644,
                },
                {
                    "op": "create",
                    "path": "NEW.txt",
                    "content_utf8": "new\n",
                    "mode": 0o644,
                },
                {
                    "op": "rename",
                    "from_path": "OLD.txt",
                    "to_path": "RENAMED.txt",
                    "expected_sha256": file_hash(b"old\n"),
                },
                {
                    "op": "delete",
                    "path": "sub/C.txt",
                    "expected_sha256": file_hash(b"gamma\n"),
                },
            ],
        }
        path = td / "instruction.json"
        path.write_text(json.dumps(instruction), encoding="utf-8")
        return path

    def test_preserves_undeclared_entries_and_applies_only_declared_changes(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            instruction_path = self.write_instruction(td, baseline)
            instruction = crm.validate_instruction(crm.load_json(instruction_path))
            plan = crm.build_plan(baseline, instruction)
            _, before = crm.load_package_state(baseline)
            after = crm.apply_operations(before, plan["operations"])

            ok, changed, unauthorized = crm.validate_preservation(
                before, after, plan["declared_paths"]
            )
            self.assertTrue(ok)
            self.assertEqual(unauthorized, [])
            self.assertEqual(
                changed,
                ["A.txt", "NEW.txt", "OLD.txt", "RENAMED.txt", "sub/C.txt"],
            )
            self.assertEqual(crm.record_hash(before["B.txt"]), crm.record_hash(after["B.txt"]))
            self.assertEqual(crm.record_hash(before["sub"]), crm.record_hash(after["sub"]))

    def test_candidate_is_deterministic(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            instruction_path = self.write_instruction(td, baseline)
            instruction = crm.validate_instruction(crm.load_json(instruction_path))
            plan = crm.build_plan(baseline, instruction)
            root, before = crm.load_package_state(baseline)
            after = crm.apply_operations(before, plan["operations"])
            one = td / "one.tar.gz"
            two = td / "two.tar.gz"
            crm.write_archive(after, one, root_name=root)
            crm.write_archive(after, two, root_name=root)
            self.assertEqual(crm.sha256_file(one), crm.sha256_file(two))
            self.assertEqual(one.read_bytes(), two.read_bytes())

    def test_baseline_is_unchanged_and_rewind_is_exact(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            original = baseline.read_bytes()
            restored = td / "restored.tar.gz"
            args = type("Args", (), {"baseline": str(baseline), "output": str(restored)})
            self.assertEqual(crm.cmd_rewind(args), 0)
            self.assertEqual(baseline.read_bytes(), original)
            self.assertEqual(restored.read_bytes(), original)

    def test_wrong_expected_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            _, state = crm.load_package_state(baseline)
            ops = [{
                "op": "replace",
                "path": "A.txt",
                "expected_sha256": "0" * 64,
                "content_base64": "WA==",
                "mode": 0o644,
            }]
            with self.assertRaises(crm.CleanRoomError):
                crm.apply_operations(state, ops)

    def test_path_traversal_is_rejected(self):
        with self.assertRaises(crm.CleanRoomError):
            crm.safe_relpath("../escape")

    def test_full_apply_and_verify(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            instruction = self.write_instruction(td, baseline)
            candidate = td / "candidate.tar.gz"
            audit = td / "audit.json"

            apply_args = type("Args", (), {
                "baseline": str(baseline),
                "instruction": str(instruction),
                "output": str(candidate),
                "audit": str(audit),
            })
            verify_args = type("Args", (), {
                "baseline": str(baseline),
                "instruction": str(instruction),
                "candidate": str(candidate),
            })

            self.assertEqual(crm.cmd_apply(apply_args), 0)
            self.assertEqual(crm.cmd_verify(verify_args), 0)
            record = json.loads(audit.read_text(encoding="utf-8"))
            self.assertEqual(record["preservation_invariant"], "PASS")
            self.assertEqual(record["unauthorized_changed_paths"], [])


    def test_apply_rejects_output_equal_to_baseline(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            instruction = self.write_instruction(td, baseline)
            original = baseline.read_bytes()
            args = type("Args", (), {
                "baseline": str(baseline),
                "instruction": str(instruction),
                "output": str(baseline),
                "audit": str(td / "audit.json"),
            })
            with self.assertRaises(crm.CleanRoomError):
                crm.cmd_apply(args)
            self.assertEqual(baseline.read_bytes(), original)

    def test_plan_and_audit_reject_protected_path_collisions(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            instruction = self.write_instruction(td, baseline)
            original = baseline.read_bytes()
            plan_args = type("Args", (), {
                "baseline": str(baseline),
                "instruction": str(instruction),
                "output": str(baseline),
            })
            with self.assertRaises(crm.CleanRoomError):
                crm.cmd_plan(plan_args)
            self.assertEqual(baseline.read_bytes(), original)

            candidate = td / "candidate.tar.gz"
            apply_args = type("Args", (), {
                "baseline": str(baseline),
                "instruction": str(instruction),
                "output": str(candidate),
                "audit": str(candidate),
            })
            with self.assertRaises(crm.CleanRoomError):
                crm.cmd_apply(apply_args)
            self.assertFalse(candidate.exists())

    def test_rewind_rejects_output_equal_to_baseline(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            original = baseline.read_bytes()
            args = type("Args", (), {"baseline": str(baseline), "output": str(baseline)})
            with self.assertRaises(crm.CleanRoomError):
                crm.cmd_rewind(args)
            self.assertEqual(baseline.read_bytes(), original)

    def test_root_metadata_is_preserved_and_hashed(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            state = {
                "": crm._entry_record(
                    kind="dir", mode=0o711, uid=91, gid=92,
                    uname="root-user", gname="root-group", mtime=777
                ),
                "A.txt": crm._entry_record(
                    kind="file", data=b"alpha\n", mode=0o644,
                    uid=11, gid=12, uname="u", gname="g", mtime=100
                ),
            }
            baseline = td / "baseline.tar.gz"
            crm.write_archive(state, baseline, root_name="system")
            instruction_data = {
                "format": crm.FORMAT,
                "baseline_sha256": crm.sha256_file(baseline),
                "operations": [{
                    "op": "replace", "path": "A.txt",
                    "expected_sha256": file_hash(b"alpha\n"),
                    "content_utf8": "ALPHA\n",
                }],
            }
            instruction = td / "instruction.json"
            instruction.write_text(json.dumps(instruction_data), encoding="utf-8")
            candidate = td / "candidate.tar.gz"
            audit = td / "audit.json"
            args = type("Args", (), {
                "baseline": str(baseline), "instruction": str(instruction),
                "output": str(candidate), "audit": str(audit),
            })
            self.assertEqual(crm.cmd_apply(args), 0)
            _, before = crm.load_package_state(baseline)
            _, after = crm.load_package_state(candidate)
            self.assertEqual(crm.record_hash(before[""]), crm.record_hash(after[""]))
            self.assertEqual(before[""], after[""])

    def test_replace_without_mode_preserves_existing_mode(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            state = {
                "A.sh": crm._entry_record(
                    kind="file", data=b"old\n", mode=0o755,
                    uid=1, gid=2, uname="u", gname="g", mtime=3
                )
            }
            baseline = td / "baseline.tar.gz"
            crm.write_archive(state, baseline, root_name="system")
            instruction = crm.validate_instruction({
                "format": crm.FORMAT,
                "baseline_sha256": crm.sha256_file(baseline),
                "operations": [{
                    "op": "replace", "path": "A.sh",
                    "expected_sha256": file_hash(b"old\n"),
                    "content_utf8": "new\n",
                }],
            })
            _, before = crm.load_package_state(baseline)
            after = crm.apply_operations(before, instruction["operations"])
            self.assertEqual(after["A.sh"]["mode"], 0o755)

    def test_replace_with_explicit_mode_changes_mode(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            _, before = crm.load_package_state(baseline)
            ops = crm.validate_instruction({
                "format": crm.FORMAT,
                "baseline_sha256": crm.sha256_file(baseline),
                "operations": [{
                    "op": "replace", "path": "A.txt",
                    "expected_sha256": file_hash(b"alpha\n"),
                    "content_utf8": "new\n", "mode": 0o600,
                }],
            })["operations"]
            after = crm.apply_operations(before, ops)
            self.assertEqual(after["A.txt"]["mode"], 0o600)

    def test_preserves_pax_metadata_global_pax_and_fractional_mtime(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = td / "baseline.tar.gz"
            with baseline.open("wb") as raw_file:
                with gzip.GzipFile(
                    filename="", mode="wb", fileobj=raw_file, mtime=0
                ) as gz:
                    with tarfile.open(
                        fileobj=gz, mode="w", format=tarfile.PAX_FORMAT,
                        pax_headers={"comment": "GLOBAL"},
                    ) as tf:
                        root = tarfile.TarInfo("system")
                        root.type = tarfile.DIRTYPE
                        root.mtime = 1
                        root.pax_headers = {"root-note": "preserve"}
                        tf.addfile(root)

                        declared = tarfile.TarInfo("system/A.txt")
                        declared.size = len(b"alpha\n")
                        declared.mtime = 10
                        tf.addfile(declared, io.BytesIO(b"alpha\n"))

                        protected = tarfile.TarInfo("system/B.txt")
                        protected.size = len(b"beta\n")
                        protected.mtime = 20.5
                        protected.pax_headers = {
                            "comment": "LOCAL",
                            "SCHILY.xattr.user.test": "abc",
                        }
                        tf.addfile(protected, io.BytesIO(b"beta\n"))

            instruction_data = {
                "format": crm.FORMAT,
                "baseline_sha256": crm.sha256_file(baseline),
                "operations": [{
                    "op": "replace", "path": "A.txt",
                    "expected_sha256": file_hash(b"alpha\n"),
                    "content_utf8": "ALPHA\n",
                }],
            }
            instruction = td / "instruction.json"
            instruction.write_text(json.dumps(instruction_data), encoding="utf-8")
            candidate = td / "candidate.tar.gz"
            audit = td / "audit.json"
            args = type("Args", (), {
                "baseline": str(baseline), "instruction": str(instruction),
                "output": str(candidate), "audit": str(audit),
            })

            self.assertEqual(crm.cmd_apply(args), 0)
            _, before = crm.load_package_state(baseline)
            _, after = crm.load_package_state(candidate)
            self.assertEqual(before[""], after[""])
            self.assertEqual(before["B.txt"], after["B.txt"])
            self.assertEqual(after["B.txt"]["mtime"], "20.5")
            self.assertEqual(
                after["B.txt"]["pax_headers"],
                {"comment": "LOCAL", "SCHILY.xattr.user.test": "abc"},
            )
            self.assertEqual(after[""]["archive_pax_headers"], {"comment": "GLOBAL"})

    def test_rename_regenerates_structural_pax_path(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            source = "source_" + ("a" * 120) + ".txt"
            target = "target_" + ("b" * 120) + ".txt"
            state = {
                source: crm._entry_record(
                    kind="file", data=b"payload\n", mode=0o644,
                    uid=1, gid=2, uname="u", gname="g", mtime=3.25,
                    pax_headers={"comment": "preserve"},
                )
            }
            baseline = td / "baseline.tar.gz"
            crm.write_archive(state, baseline, root_name="system")
            instruction_data = {
                "format": crm.FORMAT,
                "baseline_sha256": crm.sha256_file(baseline),
                "operations": [{
                    "op": "rename", "from_path": source, "to_path": target,
                    "expected_sha256": file_hash(b"payload\n"),
                }],
            }
            instruction = td / "instruction.json"
            instruction.write_text(json.dumps(instruction_data), encoding="utf-8")
            candidate = td / "candidate.tar.gz"
            audit = td / "audit.json"
            args = type("Args", (), {
                "baseline": str(baseline), "instruction": str(instruction),
                "output": str(candidate), "audit": str(audit),
            })

            self.assertEqual(crm.cmd_apply(args), 0)
            _, after = crm.load_package_state(candidate)
            self.assertNotIn(source, after)
            self.assertIn(target, after)
            self.assertEqual(after[target]["data"], b"payload\n")
            self.assertEqual(after[target]["mtime"], "3.25")
            self.assertEqual(after[target]["pax_headers"], {"comment": "preserve"})

    def test_sparse_member_is_rejected_instead_of_false_preservation(self):
        member = tarfile.TarInfo("system/sparse.bin")
        member.type = tarfile.GNUTYPE_SPARSE
        with self.assertRaises(crm.CleanRoomError):
            crm._assert_supported_member(member, member.name)


    def test_literal_backslash_path_is_preserved_without_rewrite(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            protected = "back\\slash.txt"
            state = {
                "A.txt": crm._entry_record(
                    kind="file", data=b"alpha\n", mode=0o644,
                    uid=1, gid=2, uname="u", gname="g", mtime=1,
                ),
                protected: crm._entry_record(
                    kind="file", data=b"protected\n", mode=0o600,
                    uid=3, gid=4, uname="u2", gname="g2", mtime=2,
                ),
            }
            baseline = td / "baseline.tar.gz"
            crm.write_archive(state, baseline, root_name="system")
            instruction = td / "instruction.json"
            instruction.write_text(json.dumps({
                "format": crm.FORMAT,
                "baseline_sha256": crm.sha256_file(baseline),
                "operations": [{
                    "op": "replace", "path": "A.txt",
                    "expected_sha256": file_hash(b"alpha\n"),
                    "content_utf8": "ALPHA\n",
                }],
            }), encoding="utf-8")
            candidate = td / "candidate.tar.gz"
            audit = td / "audit.json"
            args = type("Args", (), {
                "baseline": str(baseline), "instruction": str(instruction),
                "output": str(candidate), "audit": str(audit),
            })
            self.assertEqual(crm.cmd_apply(args), 0)
            _, before = crm.load_package_state(baseline)
            _, after = crm.load_package_state(candidate)
            self.assertIn(protected, after)
            self.assertNotIn("back/slash.txt", after)
            self.assertEqual(before[protected], after[protected])
            self.assertEqual(crm.safe_relpath(protected), protected)
            with self.assertRaises(crm.CleanRoomError):
                crm.safe_relpath("a//b")
            with self.assertRaises(crm.CleanRoomError):
                crm.safe_relpath("a/./b")

    def test_invalid_file_parent_hierarchy_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            archive = td / "invalid.tar"
            with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as tf:
                root = tarfile.TarInfo("root")
                root.type = tarfile.DIRTYPE
                tf.addfile(root)
                parent = tarfile.TarInfo("root/node")
                parent.size = 1
                tf.addfile(parent, io.BytesIO(b"x"))
                child = tarfile.TarInfo("root/node/child.txt")
                child.size = 1
                tf.addfile(child, io.BytesIO(b"y"))
            with self.assertRaisesRegex(crm.CleanRoomError, "invalid hierarchy"):
                crm.load_package_state(archive)

    def test_create_and_rename_hierarchy_conflicts_are_rejected(self):
        root = crm._entry_record(
            kind="dir", mode=0o755, uid=0, gid=0,
            uname="", gname="", mtime=0,
        )
        state = {
            "": root,
            "node": crm._entry_record(
                kind="file", data=b"x", mode=0o644,
                uid=0, gid=0, uname="", gname="", mtime=0,
            ),
        }
        with self.assertRaisesRegex(crm.CleanRoomError, "invalid hierarchy"):
            crm.apply_operations(state, [{
                "op": "create", "path": "node/child.txt",
                "content_base64": base64.b64encode(b"y").decode("ascii"),
                "mode": 0o644,
            }])

        state_two = {
            "": root,
            "source.txt": crm._entry_record(
                kind="file", data=b"s", mode=0o644,
                uid=0, gid=0, uname="", gname="", mtime=0,
            ),
            "branch/leaf.txt": crm._entry_record(
                kind="file", data=b"l", mode=0o644,
                uid=0, gid=0, uname="", gname="", mtime=0,
            ),
        }
        with self.assertRaisesRegex(crm.CleanRoomError, "invalid hierarchy"):
            crm.apply_operations(state_two, [{
                "op": "rename", "from_path": "source.txt", "to_path": "branch",
                "expected_sha256": file_hash(b"s"),
            }])

    def test_baseline_snapshot_remains_bound_if_path_is_replaced_after_read(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            replacement = td / "replacement.tar.gz"
            replacement_state = {
                "A.txt": crm._entry_record(
                    kind="file", data=b"alpha\n", mode=0o644,
                    uid=11, gid=12, uname="u", gname="g", mtime=100,
                ),
                "B.txt": crm._entry_record(
                    kind="file", data=b"different\n", mode=0o600,
                    uid=21, gid=22, uname="u2", gname="g2", mtime=200,
                ),
            }
            crm.write_archive(replacement_state, replacement, root_name="system")
            original_sha = crm.sha256_file(baseline)
            instruction = td / "instruction.json"
            instruction.write_text(json.dumps({
                "format": crm.FORMAT,
                "baseline_sha256": original_sha,
                "operations": [{
                    "op": "replace", "path": "A.txt",
                    "expected_sha256": file_hash(b"alpha\n"),
                    "content_utf8": "ALPHA\n",
                }],
            }), encoding="utf-8")
            candidate = td / "candidate.tar.gz"
            audit = td / "audit.json"
            original_reader = crm.read_file_snapshot
            replaced = {"done": False}

            def hooked(path):
                snapshot = original_reader(path)
                if Path(path) == baseline and not replaced["done"]:
                    baseline.write_bytes(replacement.read_bytes())
                    replaced["done"] = True
                return snapshot

            args = type("Args", (), {
                "baseline": str(baseline), "instruction": str(instruction),
                "output": str(candidate), "audit": str(audit),
            })
            with mock.patch.object(crm, "read_file_snapshot", side_effect=hooked):
                self.assertEqual(crm.cmd_apply(args), 0)

            _, candidate_state = crm.load_package_state(candidate)
            self.assertEqual(candidate_state["B.txt"]["data"], b"beta\n")
            record = json.loads(audit.read_text(encoding="utf-8"))
            self.assertEqual(record["baseline_sha256"], original_sha)
            self.assertEqual(record["instruction_baseline_sha256"], original_sha)
            self.assertEqual(record["baseline_snapshot_binding"], "PASS")

    def test_prepublication_failure_preserves_existing_candidate_and_audit(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            instruction = self.write_instruction(td, baseline)
            candidate = td / "candidate.tar.gz"
            audit = td / "audit.json"
            candidate.write_bytes(b"OLD CANDIDATE")
            audit.write_bytes(b"OLD AUDIT")
            original_loader = crm.load_package_snapshot

            def hooked(path):
                if ".candidate.tmp" in Path(path).name:
                    raise crm.CleanRoomError("forced candidate verification failure")
                return original_loader(path)

            args = type("Args", (), {
                "baseline": str(baseline), "instruction": str(instruction),
                "output": str(candidate), "audit": str(audit),
            })
            with mock.patch.object(crm, "load_package_snapshot", side_effect=hooked):
                with self.assertRaisesRegex(crm.CleanRoomError, "forced"):
                    crm.cmd_apply(args)
            self.assertEqual(candidate.read_bytes(), b"OLD CANDIDATE")
            self.assertEqual(audit.read_bytes(), b"OLD AUDIT")

    def test_missing_audit_parent_is_rejected_before_candidate_change(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            instruction = self.write_instruction(td, baseline)
            candidate = td / "candidate.tar.gz"
            candidate.write_bytes(b"OLD CANDIDATE")
            args = type("Args", (), {
                "baseline": str(baseline), "instruction": str(instruction),
                "output": str(candidate),
                "audit": str(td / "missing" / "audit.json"),
            })
            with self.assertRaisesRegex(crm.CleanRoomError, "parent directory"):
                crm.cmd_apply(args)
            self.assertEqual(candidate.read_bytes(), b"OLD CANDIDATE")

    def test_publication_failure_rolls_back_both_existing_outputs(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            instruction = self.write_instruction(td, baseline)
            candidate = td / "candidate.tar.gz"
            audit = td / "audit.json"
            candidate.write_bytes(b"OLD CANDIDATE")
            audit.write_bytes(b"OLD AUDIT")
            original_replace = os.replace

            def hooked(source, destination):
                source_path = Path(source)
                destination_path = Path(destination)
                if destination_path == candidate and ".candidate.tmp" in source_path.name:
                    raise OSError("forced publication failure")
                return original_replace(source, destination)

            args = type("Args", (), {
                "baseline": str(baseline), "instruction": str(instruction),
                "output": str(candidate), "audit": str(audit),
            })
            with mock.patch.object(crm.os, "replace", side_effect=hooked):
                with self.assertRaisesRegex(crm.CleanRoomError, "publication"):
                    crm.cmd_apply(args)
            self.assertEqual(candidate.read_bytes(), b"OLD CANDIDATE")
            self.assertEqual(audit.read_bytes(), b"OLD AUDIT")

    def test_mid_archive_global_pax_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            archive = td / "mid-global.tar"
            with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as tf:
                root = tarfile.TarInfo("root")
                root.type = tarfile.DIRTYPE
                tf.addfile(root)
                first = tarfile.TarInfo("root/a")
                first.size = 1
                tf.addfile(first, io.BytesIO(b"a"))
                block = tarfile.TarInfo._create_pax_generic_header(
                    {"uid": "123"}, tarfile.XGLTYPE, "utf-8"
                )
                tf.fileobj.write(block)
                tf.offset += len(block)
                second = tarfile.TarInfo("root/b")
                second.size = 1
                tf.addfile(second, io.BytesIO(b"b"))
            with self.assertRaisesRegex(crm.CleanRoomError, "mid-archive global PAX"):
                crm.load_package_state(archive)

    def test_exact_high_precision_pax_mtime_is_preserved(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            exact = "20.123456789123456789"
            baseline = td / "baseline.tar.gz"
            with baseline.open("wb") as raw_file:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw_file, mtime=0) as gz:
                    with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
                        root = tarfile.TarInfo("system")
                        root.type = tarfile.DIRTYPE
                        tf.addfile(root)
                        declared = tarfile.TarInfo("system/A.txt")
                        declared.size = len(b"alpha\n")
                        tf.addfile(declared, io.BytesIO(b"alpha\n"))
                        protected = tarfile.TarInfo("system/B.txt")
                        protected.size = len(b"beta\n")
                        protected.mtime = 20
                        protected.pax_headers = {"mtime": exact}
                        tf.addfile(protected, io.BytesIO(b"beta\n"))
            instruction = td / "instruction.json"
            instruction.write_text(json.dumps({
                "format": crm.FORMAT,
                "baseline_sha256": crm.sha256_file(baseline),
                "operations": [{
                    "op": "replace", "path": "A.txt",
                    "expected_sha256": file_hash(b"alpha\n"),
                    "content_utf8": "ALPHA\n",
                }],
            }), encoding="utf-8")
            candidate = td / "candidate.tar.gz"
            audit = td / "audit.json"
            args = type("Args", (), {
                "baseline": str(baseline), "instruction": str(instruction),
                "output": str(candidate), "audit": str(audit),
            })
            self.assertEqual(crm.cmd_apply(args), 0)
            _, before = crm.load_package_state(baseline)
            _, after = crm.load_package_state(candidate)
            self.assertEqual(before["B.txt"]["mtime"], exact)
            self.assertEqual(after["B.txt"]["mtime"], exact)
            self.assertEqual(before["B.txt"], after["B.txt"])
            with tarfile.open(candidate, "r:*") as tf:
                member = tf.getmember("system/B.txt")
                self.assertEqual(member.pax_headers["mtime"], exact)

    def test_non_utf8_archive_path_is_rejected_as_controlled_error(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            archive = td / "nonutf8.tar"
            with tarfile.open(
                archive, "w", format=tarfile.PAX_FORMAT,
                encoding="utf-8", errors="surrogateescape",
            ) as tf:
                root = tarfile.TarInfo("root")
                root.type = tarfile.DIRTYPE
                tf.addfile(root)
                bad = tarfile.TarInfo("root/bad\udcff")
                bad.size = 1
                tf.addfile(bad, io.BytesIO(b"x"))
            with self.assertRaisesRegex(crm.CleanRoomError, "valid UTF-8"):
                crm.load_package_state(archive)

    def test_sha256_fields_are_strict_and_uppercase_is_normalized(self):
        with self.assertRaisesRegex(crm.CleanRoomError, "hexadecimal"):
            crm.validate_instruction({
                "format": crm.FORMAT,
                "baseline_sha256": "z" * 64,
                "operations": [{"op": "create", "path": "A", "content_utf8": "x"}],
            })
        normalized = crm.validate_instruction({
            "format": crm.FORMAT,
            "baseline_sha256": "A" * 64,
            "operations": [{
                "op": "delete", "path": "A",
                "expected_sha256": "B" * 64,
            }],
        })
        self.assertEqual(normalized["baseline_sha256"], "a" * 64)
        self.assertEqual(normalized["operations"][0]["expected_sha256"], "b" * 64)

    def test_boolean_modes_are_rejected(self):
        for value in (True, False):
            with self.subTest(value=value):
                with self.assertRaisesRegex(crm.CleanRoomError, "mode must be an integer"):
                    crm.validate_instruction({
                        "format": crm.FORMAT,
                        "baseline_sha256": "0" * 64,
                        "operations": [{
                            "op": "create", "path": "A",
                            "content_utf8": "x", "mode": value,
                        }],
                    })


    def test_unknown_instruction_fields_are_rejected_before_outputs(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_baseline(td)
            instruction = {
                "format": crm.FORMAT,
                "baseline_sha256": crm.sha256_file(baseline),
                "operations": [{
                    "op": "create",
                    "path": "NEW.txt",
                    "content_utf8": "new\n",
                }],
                "extra": True,
            }
            instruction_path = td / "instruction.json"
            instruction_path.write_text(
                json.dumps(instruction), encoding="utf-8"
            )
            candidate = td / "candidate.tar.gz"
            audit = td / "audit.json"
            args = type("Args", (), {
                "baseline": str(baseline),
                "instruction": str(instruction_path),
                "output": str(candidate),
                "audit": str(audit),
            })

            with self.assertRaisesRegex(
                crm.CleanRoomError,
                r"instruction contains unsupported fields: \['extra'\]",
            ):
                crm.cmd_apply(args)
            self.assertFalse(candidate.exists())
            self.assertFalse(audit.exists())

    def test_operation_specific_unknown_fields_are_rejected(self):
        cases = [
            (
                "create",
                {
                    "op": "create", "path": "A",
                    "content_utf8": "x", "mod": 0o600,
                },
                "mod",
            ),
            (
                "replace",
                {
                    "op": "replace", "path": "A",
                    "expected_sha256": "1" * 64,
                    "content_utf8": "x", "from_path": "B",
                },
                "from_path",
            ),
            (
                "delete-content-utf8",
                {
                    "op": "delete", "path": "A",
                    "expected_sha256": "1" * 64,
                    "content_utf8": "x",
                },
                "content_utf8",
            ),
            (
                "delete-content-base64",
                {
                    "op": "delete", "path": "A",
                    "expected_sha256": "1" * 64,
                    "content_base64": "eA==",
                },
                "content_base64",
            ),
            (
                "delete-mode",
                {
                    "op": "delete", "path": "A",
                    "expected_sha256": "1" * 64, "mode": 0o600,
                },
                "mode",
            ),
            (
                "delete-from-path",
                {
                    "op": "delete", "path": "A",
                    "expected_sha256": "1" * 64, "from_path": "B",
                },
                "from_path",
            ),
            (
                "delete-to-path",
                {
                    "op": "delete", "path": "A",
                    "expected_sha256": "1" * 64, "to_path": "B",
                },
                "to_path",
            ),
            (
                "rename-path",
                {
                    "op": "rename", "from_path": "A", "to_path": "B",
                    "expected_sha256": "1" * 64, "path": "A",
                },
                "path",
            ),
            (
                "rename-content-utf8",
                {
                    "op": "rename", "from_path": "A", "to_path": "B",
                    "expected_sha256": "1" * 64,
                    "content_utf8": "x",
                },
                "content_utf8",
            ),
            (
                "rename-content-base64",
                {
                    "op": "rename", "from_path": "A", "to_path": "B",
                    "expected_sha256": "1" * 64,
                    "content_base64": "eA==",
                },
                "content_base64",
            ),
            (
                "rename-mode",
                {
                    "op": "rename", "from_path": "A", "to_path": "B",
                    "expected_sha256": "1" * 64, "mode": 0o600,
                },
                "mode",
            ),
        ]

        for name, operation, field in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    crm.CleanRoomError,
                    rf"contains unsupported fields: \['{field}'\]",
                ):
                    crm.validate_instruction({
                        "format": crm.FORMAT,
                        "baseline_sha256": "0" * 64,
                        "operations": [operation],
                    })

    def test_unknown_field_errors_are_sorted_deterministically(self):
        with self.assertRaisesRegex(
            crm.CleanRoomError,
            r"contains unsupported fields: \['alpha', 'zeta'\]",
        ):
            crm.validate_instruction({
                "format": crm.FORMAT,
                "baseline_sha256": "0" * 64,
                "operations": [{
                    "op": "delete", "path": "A",
                    "expected_sha256": "1" * 64,
                    "zeta": 1, "alpha": 2,
                }],
            })

    def test_closed_schema_accepts_supported_operation_shapes(self):
        cases = [
            {
                "op": "create", "path": "A",
                "content_utf8": "x",
            },
            {
                "op": "create", "path": "A",
                "content_base64": "eA==",
            },
            {
                "op": "create", "path": "A",
                "content_utf8": "x", "mode": 0o600,
            },
            {
                "op": "replace", "path": "A",
                "expected_sha256": "1" * 64,
                "content_utf8": "x",
            },
            {
                "op": "replace", "path": "A",
                "expected_sha256": "1" * 64,
                "content_base64": "eA==",
            },
            {
                "op": "replace", "path": "A",
                "expected_sha256": "1" * 64,
                "content_utf8": "x", "mode": 0o600,
            },
            {
                "op": "delete", "path": "A",
                "expected_sha256": "1" * 64,
            },
            {
                "op": "rename", "from_path": "A", "to_path": "B",
                "expected_sha256": "1" * 64,
            },
        ]

        for operation in cases:
            with self.subTest(operation=operation):
                normalized = crm.validate_instruction({
                    "format": crm.FORMAT,
                    "baseline_sha256": "0" * 64,
                    "operations": [operation],
                })
                self.assertEqual(normalized["operations"][0]["op"], operation["op"])

    def _write_raw_instruction(self, td: Path, text: str) -> Path:
        path = td / "raw_instruction.json"
        path.write_text(text, encoding="utf-8")
        return path

    def test_duplicate_operation_field_is_rejected_during_json_parse(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            path = self._write_raw_instruction(
                td,
                '{"format":"cleanroom-mutator-instruction/v1",'
                '"baseline_sha256":"' + ('0' * 64) + '",'
                '"operations":[{"op":"create","op":"delete",'
                '"path":"A","content_utf8":"x"}]}'
            )
            with self.assertRaisesRegex(
                crm.CleanRoomError,
                r"duplicate JSON object fields are forbidden: \['op'\]",
            ):
                crm.load_json(path)

    def test_duplicate_mode_is_rejected_before_normalization(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            path = self._write_raw_instruction(
                td,
                '{"format":"cleanroom-mutator-instruction/v1",'
                '"baseline_sha256":"' + ('0' * 64) + '",'
                '"operations":[{"op":"create","path":"A",'
                '"content_utf8":"x","mode":384,"mode":420}]}'
            )
            with self.assertRaisesRegex(
                crm.CleanRoomError,
                r"duplicate JSON object fields are forbidden: \['mode'\]",
            ):
                crm.load_json(path)

    def test_duplicate_top_level_baseline_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            path = self._write_raw_instruction(
                td,
                '{"format":"cleanroom-mutator-instruction/v1",'
                '"baseline_sha256":"' + ('0' * 64) + '",'
                '"baseline_sha256":"' + ('1' * 64) + '",'
                '"operations":[{"op":"create","path":"A",'
                '"content_utf8":"x"}]}'
            )
            with self.assertRaisesRegex(
                crm.CleanRoomError,
                r"duplicate JSON object fields are forbidden: \['baseline_sha256'\]",
            ):
                crm.load_json(path)

    def test_identical_duplicate_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            path = self._write_raw_instruction(
                td,
                '{"format":"cleanroom-mutator-instruction/v1",'
                '"baseline_sha256":"' + ('0' * 64) + '",'
                '"operations":[{"op":"create","path":"A","path":"A",'
                '"content_utf8":"x"}]}'
            )
            with self.assertRaisesRegex(
                crm.CleanRoomError,
                r"duplicate JSON object fields are forbidden: \['path'\]",
            ):
                crm.load_json(path)

    def test_duplicate_field_error_order_is_deterministic(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            path = self._write_raw_instruction(
                td,
                '{"format":"cleanroom-mutator-instruction/v1",'
                '"baseline_sha256":"' + ('0' * 64) + '",'
                '"operations":[{"op":"create","path":"A",'
                '"content_utf8":"x","mode":384,'
                '"content_utf8":"y","mode":420}]}'
            )
            with self.assertRaisesRegex(
                crm.CleanRoomError,
                r"duplicate JSON object fields are forbidden: "
                r"\['content_utf8', 'mode'\]",
            ):
                crm.load_json(path)

    def test_duplicate_free_json_parse_and_normalization_are_compatible(self):
        instruction_text = json.dumps({
            "format": crm.FORMAT,
            "baseline_sha256": "0" * 64,
            "operations": [
                {"op": "create", "path": "A", "content_utf8": "x"},
                {
                    "op": "replace", "path": "B",
                    "expected_sha256": "1" * 64,
                    "content_base64": "eA==", "mode": 0o600,
                },
                {
                    "op": "delete", "path": "C",
                    "expected_sha256": "2" * 64,
                },
                {
                    "op": "rename", "from_path": "D", "to_path": "E",
                    "expected_sha256": "3" * 64,
                },
            ],
        })
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            path = self._write_raw_instruction(td, instruction_text)
            strict_parsed = crm.load_json(path)
            ordinary_parsed = json.loads(instruction_text)
            self.assertEqual(strict_parsed, ordinary_parsed)
            self.assertEqual(
                crm.validate_instruction(strict_parsed),
                crm.validate_instruction(ordinary_parsed),
            )

    def make_nonzero_directory_archive(
        self, td: Path, *, nested: bool, size: int = 24
    ) -> Path:
        path = td / ("nested-nonzero.tar.gz" if nested else "root-nonzero.tar.gz")
        payload = b"D" * size
        with path.open("wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=0
            ) as gz:
                with tarfile.open(
                    fileobj=gz, mode="w", format=tarfile.PAX_FORMAT
                ) as tf:
                    root = tarfile.TarInfo("system")
                    root.type = tarfile.DIRTYPE
                    root.mode = 0o755
                    root.size = 0 if nested else size
                    tf.addfile(root, None if nested else io.BytesIO(payload))

                    if nested:
                        directory = tarfile.TarInfo("system/dir")
                        directory.type = tarfile.DIRTYPE
                        directory.mode = 0o755
                        directory.size = size
                        tf.addfile(directory, io.BytesIO(payload))

                    following = tarfile.TarInfo("system/AFTER.txt")
                    following.mode = 0o644
                    following.size = 5
                    tf.addfile(following, io.BytesIO(b"after"))
        return path

    def test_nested_nonzero_directory_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_nonzero_directory_archive(td, nested=True)
            with self.assertRaisesRegex(
                crm.CleanRoomError,
                r"directory archive entry must have size 0: system/dir: 24",
            ):
                crm.load_package_state(baseline)

    def test_root_nonzero_directory_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_nonzero_directory_archive(td, nested=False)
            with self.assertRaisesRegex(
                crm.CleanRoomError,
                r"directory archive entry must have size 0: system: 24",
            ):
                crm.load_package_state(baseline)

    def test_nonzero_directory_rejection_creates_no_outputs(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_nonzero_directory_archive(td, nested=True)
            instruction = td / "instruction.json"
            instruction.write_text(json.dumps({
                "format": crm.FORMAT,
                "baseline_sha256": crm.sha256_file(baseline),
                "operations": [{
                    "op": "create", "path": "NEW.txt",
                    "content_utf8": "new",
                }],
            }), encoding="utf-8")
            candidate = td / "candidate.tar.gz"
            audit = td / "candidate.audit.json"
            args = type("Args", (), {
                "baseline": str(baseline),
                "instruction": str(instruction),
                "output": str(candidate),
                "audit": str(audit),
            })
            with self.assertRaisesRegex(
                crm.CleanRoomError,
                r"directory archive entry must have size 0",
            ):
                crm.cmd_apply(args)
            self.assertFalse(candidate.exists())
            self.assertFalse(audit.exists())

    def test_nonzero_directory_rejection_preserves_existing_outputs(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            baseline = self.make_nonzero_directory_archive(td, nested=True)
            instruction = td / "instruction.json"
            instruction.write_text(json.dumps({
                "format": crm.FORMAT,
                "baseline_sha256": crm.sha256_file(baseline),
                "operations": [{
                    "op": "create", "path": "NEW.txt",
                    "content_utf8": "new",
                }],
            }), encoding="utf-8")
            candidate = td / "candidate.tar.gz"
            audit = td / "candidate.audit.json"
            candidate.write_bytes(b"old candidate")
            audit.write_bytes(b"old audit")
            args = type("Args", (), {
                "baseline": str(baseline),
                "instruction": str(instruction),
                "output": str(candidate),
                "audit": str(audit),
            })
            with self.assertRaises(crm.CleanRoomError):
                crm.cmd_apply(args)
            self.assertEqual(candidate.read_bytes(), b"old candidate")
            self.assertEqual(audit.read_bytes(), b"old audit")

    def test_entry_record_rejects_nonempty_directory_data(self):
        with self.assertRaisesRegex(
            crm.CleanRoomError, r"directory entry data must be empty"
        ):
            crm._entry_record(
                kind="dir", data=b"payload", mode=0o755,
                uid=0, gid=0, uname="", gname="", mtime=0,
            )

    def test_state_validation_rejects_nonempty_directory_data(self):
        record = crm._entry_record(
            kind="dir", mode=0o755, uid=0, gid=0,
            uname="", gname="", mtime=0,
        )
        record["data"] = b"payload"
        with self.assertRaisesRegex(
            crm.CleanRoomError,
            r"directory entry data must be empty: dir",
        ):
            crm.validate_state_hierarchy({"dir": record})

    def test_write_archive_rejects_nonempty_directory_data(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            record = crm._entry_record(
                kind="dir", mode=0o755, uid=0, gid=0,
                uname="", gname="", mtime=0,
            )
            record["data"] = b"payload"
            output = td / "invalid.tar.gz"
            with self.assertRaisesRegex(
                crm.CleanRoomError,
                r"directory entry data must be empty: dir",
            ):
                crm.write_archive({"dir": record}, output, root_name="system")
            self.assertFalse(output.exists())

    def test_zero_size_directory_members_still_round_trip(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            state = {
                "": crm._entry_record(
                    kind="dir", mode=0o755, uid=0, gid=0,
                    uname="", gname="", mtime=0,
                ),
                "dir": crm._entry_record(
                    kind="dir", mode=0o750, uid=1, gid=2,
                    uname="u", gname="g", mtime=10,
                ),
                "dir/A.txt": crm._entry_record(
                    kind="file", data=b"A", mode=0o640,
                    uid=3, gid=4, uname="u2", gname="g2", mtime=20,
                ),
            }
            first = td / "first.tar.gz"
            second = td / "second.tar.gz"
            crm.write_archive(state, first, root_name="system")
            root_name, loaded = crm.load_package_state(first)
            self.assertEqual(root_name, "system")
            self.assertEqual(loaded, state)
            crm.write_archive(loaded, second, root_name=root_name)
            self.assertEqual(first.read_bytes(), second.read_bytes())


if __name__ == "__main__":
    unittest.main()
