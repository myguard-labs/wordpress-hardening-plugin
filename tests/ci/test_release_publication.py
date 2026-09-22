"""Exercise the actual publication shell with local Git tags and a fake gh."""

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release.yml"
GH_STUB = """
change_tag() {
  if [ "$1" = delete ]; then
    git --git-dir="$REMOTE" update-ref -d "refs/tags/$GITHUB_REF_NAME"
  elif [ "$1" = move ]; then
    git --git-dir="$REMOTE" update-ref "refs/tags/$GITHUB_REF_NAME" "$OLD_SHA"
  fi
}
gh() {
  printf '%s\\0' "$@" >> "$GH_CALLS"
  printf '\\n' >> "$GH_CALLS"
  if [ "$1 $2" = 'release view' ]; then
    # Simulate a tag disappearing/moving while release lookup is in flight.
    change_tag "$TAG_CHANGE"
    return "$GH_VIEW_STATUS"
  fi
  change_tag "$PUBLISH_CHANGE"
  return "$GH_PUBLISH_STATUS"
}
"""


class ReleasePublicationTest(unittest.TestCase):
    def setUp(self):
        # Git hooks export repository paths. Fixtures must never inherit them.
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        self.tmp = tempfile.TemporaryDirectory(prefix="release-test-", dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.remote = self.path / "remote.git"
        self.work = self.path / "work"
        self.work.mkdir()
        self.calls = self.path / "gh-calls"
        self.git("init", "--bare", str(self.remote))
        self.git("init", str(self.work))
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Release test")
        self.git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "old")
        self.old_sha = self.git("rev-parse", "HEAD")
        self.git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "run")
        self.sha = self.git("rev-parse", "HEAD")
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "origin", "HEAD:refs/heads/main")
        (self.work / "dist").mkdir()
        (self.work / "dist" / "asset.zip").touch()

    def git(self, *args):
        return subprocess.run(
            ["git", *args],
            cwd=self.work,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env=self.env,
        ).stdout.strip()

    def tag(self, tag="1.2.0", *, annotated=False, moved=False):
        args = ["-a", "-m", "release"] if annotated else []
        self.git(
            "-c",
            "tag.gpgsign=false",
            "tag",
            *args,
            tag,
            self.old_sha if moved else self.sha,
        )
        self.git("push", "origin", f"refs/tags/{tag}")

    def publish(
        self,
        tag="1.2.0",
        *,
        exists=False,
        change="",
        publish_status=0,
        publish_change="",
    ):
        # This is the final step in release.yml. Extract it without needing a
        # third-party YAML parser in the local or self-hosted CI environment.
        step = WORKFLOW.read_text().split("      - name: Publish release assets\n", 1)[
            1
        ]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        result = subprocess.run(
            ["bash", "-euo", "pipefail", "-c", GH_STUB + script],
            cwd=self.work,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env={
                **self.env,
                "GITHUB_REF_NAME": tag,
                "GITHUB_SHA": self.sha,
                "GH_CALLS": str(self.calls),
                "GH_VIEW_STATUS": "0" if exists else "1",
                "GH_PUBLISH_STATUS": str(publish_status),
                "TAG_CHANGE": change,
                "PUBLISH_CHANGE": publish_change,
                "REMOTE": str(self.remote),
                "OLD_SHA": self.old_sha,
            },
        )
        calls = [
            line.rstrip("\0").split("\0")
            for line in self.calls.read_text().splitlines()
        ]
        return result, calls

    def test_matching_stable_creates_verified_release(self):
        self.tag()
        result, calls = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            calls[-1],
            [
                "release",
                "create",
                "1.2.0",
                "dist/asset.zip",
                "--verify-tag",
                "--title",
                "1.2.0",
                "--generate-notes",
            ],
        )

    def test_matching_annotated_tag_uploads_existing_release(self):
        self.tag(annotated=True)
        result, calls = self.publish(exists=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            calls[-1], ["release", "upload", "1.2.0", "dist/asset.zip", "--clobber"]
        )

    def test_rc_creates_prerelease_without_latest(self):
        self.tag("1.0.0rc3", annotated=True)
        result, calls = self.publish("1.0.0rc3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            calls[-1],
            [
                "release",
                "create",
                "1.0.0rc3",
                "dist/asset.zip",
                "--verify-tag",
                "--prerelease",
                "--latest=false",
                "--title",
                "1.0.0rc3",
                "--generate-notes",
            ],
        )

    def assert_rejected(self, **kwargs):
        result, calls = self.publish(**kwargs)
        self.assertNotEqual(result.returncode, 0, "unsafe tag must stop publication")
        self.assertEqual(
            calls,
            [["release", "view", "1.2.0"]],
            "rejected tag must not create or overwrite release assets",
        )

    def test_missing_tag_cannot_be_recreated(self):
        self.assert_rejected()

    def test_moved_lightweight_tag_cannot_overwrite_assets(self):
        self.tag(moved=True)
        self.assert_rejected(exists=True)

    def test_moved_annotated_tag_cannot_create_release(self):
        self.tag(annotated=True, moved=True)
        self.assert_rejected()

    def test_tag_deleted_during_release_lookup_is_rejected(self):
        self.tag()
        self.assert_rejected(exists=True, change="delete")

    def test_tag_moved_during_release_lookup_is_rejected(self):
        self.tag()
        self.assert_rejected(change="move")

    def test_remote_lookup_error_fails_closed(self):
        self.tag()
        self.git("remote", "set-url", "origin", str(self.path / "absent.git"))
        self.assert_rejected(exists=True)

    def test_publication_error_fails_the_step(self):
        self.tag()
        for exists in (False, True):
            with self.subTest(exists=exists):
                result, _ = self.publish(exists=exists, publish_status=23)
                self.assertEqual(result.returncode, 23)

    def test_tag_changes_during_publication_fail_the_step(self):
        self.tag()
        for exists in (False, True):
            for change in ("move", "delete"):
                with self.subTest(exists=exists, change=change):
                    self.git(
                        "--git-dir=" + str(self.remote),
                        "update-ref",
                        "refs/tags/1.2.0",
                        self.sha,
                    )
                    result, calls = self.publish(exists=exists, publish_change=change)
                    self.assertEqual(calls[-1][1], "upload" if exists else "create")
                    self.assertNotEqual(
                        result.returncode, 0, "tag changed during publication must fail"
                    )

    def test_publishers_are_serialized_by_tag_without_cancellation(self):
        self.assertIn(
            "\nconcurrency:\n  group: release-${{ github.ref }}\n"
            "  cancel-in-progress: false\n",
            WORKFLOW.read_text(),
        )


if __name__ == "__main__":
    unittest.main()
