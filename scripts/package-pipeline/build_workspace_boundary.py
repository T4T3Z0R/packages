"""Verify protected pipeline paths against an unprivileged build account."""

import argparse
import os
import pwd
import stat
import sys

from pathlib import Path


class BoundaryError(ValueError):
    """A protected filesystem boundary is not established."""


def validate_workspace(workspace):
    """Require an existing absolute path without symlink components."""

    if not workspace.is_absolute():
        raise BoundaryError("Workspace path must be absolute")

    if workspace.resolve(strict=True) != workspace:
        raise BoundaryError(
            "Workspace path contains symbolic or ambiguous components"
        )

    if not workspace.is_dir():
        raise BoundaryError("Workspace is not a directory")

    if workspace == Path("/"):
        raise BoundaryError("Filesystem root cannot be a workspace")

    return workspace


def writable_roots(workspace, requested):
    """Permit exclusions only as direct children of the build parent."""

    allowed = set()

    for value in requested:
        relative = Path(value)

        if (
            relative.is_absolute()
            or len(relative.parts) != 2
            or relative.parts[0] != "build"
            or relative.parts[1] in (".", "..")
        ):
            raise BoundaryError(
                f"Invalid writable workspace exclusion: {value}"
            )

        target = workspace / relative

        if target in allowed:
            raise BoundaryError(
                f"Duplicate writable workspace exclusion: {value}"
            )

        metadata = target.lstat()

        if not stat.S_ISDIR(metadata.st_mode):
            raise BoundaryError(
                f"Writable workspace is not a real directory: {target}"
            )

        if target.resolve(strict=True) != target:
            raise BoundaryError(
                f"Writable workspace contains symlink components: {target}"
            )

        allowed.add(target)

    return allowed


def protected_entry(path, metadata, uid):
    """Reject ownership and file types incompatible with protection."""

    if metadata.st_uid == uid:
        raise BoundaryError(
            f"Protected path is owned by builder: {path}"
        )

    if not (
        stat.S_ISREG(metadata.st_mode)
        or stat.S_ISDIR(metadata.st_mode)
    ):
        raise BoundaryError(
            f"Unexpected protected filesystem entry: {path}"
        )


def verify_protected_mission_link(
    path, metadata, workspace, allowed, uid
):
    """Permit only direct, protected GameShell mission sibling links."""

    missions = workspace / "source/GameShell/missions"

    if not path.is_relative_to(missions):
        raise BoundaryError(
            f"Unexpected protected filesystem entry: {path}"
        )

    relative = path.relative_to(missions)

    # Expected layout: group/mission/asset.
    if len(relative.parts) != 3:
        raise BoundaryError(
            f"Unexpected GameShell mission link location: {path}"
        )

    if metadata.st_uid == uid:
        raise BoundaryError(
            f"Protected link is owned by builder: {path}"
        )

    raw_target = os.readlink(path)
    parts = Path(raw_target).parts

    # The selected upstream revision uses ../sibling/asset.
    if (
        len(parts) != 3
        or parts[0] != ".."
        or parts[1] in (".", "..")
        or parts[2] in (".", "..")
        or raw_target != "/".join(parts)
    ):
        raise BoundaryError(
            f"Invalid GameShell mission link target: {path}"
        )

    target = path.parent.parent / parts[1] / parts[2]

    if any(
        target == root or target.is_relative_to(root)
        for root in allowed
    ):
        raise BoundaryError(
            f"Mission link targets writable workspace: {path}"
        )

    try:
        resolved = target.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BoundaryError(
            f"Missing or invalid mission link target: {path}"
        ) from exc

    # Reject intermediate links and chained link targets.
    if resolved != target:
        raise BoundaryError(
            f"Mission link target is not a direct protected path: {path}"
        )

    protected_entry(target, target.lstat(), uid)


def collect_protected(workspace, allowed, uid):
    """Enumerate protected entries without traversing writable trees."""

    entries = []

    def visit(path):
        if path in allowed:
            return

        metadata = path.lstat()

        if stat.S_ISLNK(metadata.st_mode):
            verify_protected_mission_link(
                path, metadata, workspace, allowed, uid
            )

            # Include the link for effective target-access checking,
            # but never recurse through it.
            entries.append(path)
            return

        protected_entry(path, metadata, uid)

        entries.append(path)

        if stat.S_ISDIR(metadata.st_mode):
            with os.scandir(path) as children:
                for child in children:
                    visit(Path(child.path))

    visit(workspace)

    return entries


def collect_ancestors(workspace, uid):
    """Record each protected ancestor and its immediate child."""

    ancestors = []
    child = workspace

    while child.parent != child:
        parent = child.parent
        metadata = parent.lstat()

        if not stat.S_ISDIR(metadata.st_mode):
            raise BoundaryError(
                f"Workspace ancestor is not a real directory: {parent}"
            )

        if metadata.st_uid == uid:
            raise BoundaryError(
                f"Workspace ancestor is owned by builder: {parent}"
            )

        ancestors.append((parent, child))
        child = parent

    return ancestors


def check_effective_access(entries, ancestors, allowed, uid):
    """Run after dropping privileges to the actual builder account."""

    for path in entries:
        if os.access(path, os.W_OK):
            raise BoundaryError(
                f"Builder can write protected path: {path}"
            )

    for parent, child in ancestors:
        if not os.access(parent, os.X_OK):
            raise BoundaryError(
                f"Builder cannot traverse workspace ancestor: {parent}"
            )

        if not os.access(parent, os.W_OK | os.X_OK):
            continue

        metadata = parent.stat()

        # A sticky directory such as /tmp may be writable while
        # still preventing replacement of another owner's entry.
        if (
            metadata.st_mode & stat.S_ISVTX
            and metadata.st_uid != uid
            and child.lstat().st_uid != uid
        ):
            continue

        raise BoundaryError(
            f"Builder can replace protected path through ancestor: {parent}"
        )

    for path in allowed:
        if not os.access(path, os.W_OK | os.X_OK):
            raise BoundaryError(
                f"Builder cannot use authorized workspace: {path}"
            )


def check_docker_socket_access():
    """Reject access to conventional privileged Docker endpoints."""

    for path in (
        Path("/var/run/docker.sock"),
        Path("/run/docker.sock"),
    ):
        if os.access(path, os.W_OK):
            raise BoundaryError(
                f"Builder can access Docker control endpoint: {path}"
            )


def verify(user, workspace, requested):
    """Enumerate as root, then verify effective access in a child."""

    if os.geteuid() != 0:
        raise BoundaryError("Boundary verification requires root")

    account = pwd.getpwnam(user)

    if account.pw_uid == 0 or account.pw_gid == 0:
        raise BoundaryError("Build account must not use root UID or GID")

    workspace = validate_workspace(workspace)
    allowed = writable_roots(workspace, requested)

    for path in allowed:
        if path.lstat().st_uid != account.pw_uid:
            raise BoundaryError(
                f"Authorized workspace is not builder-owned: {path}"
            )

    entries = collect_protected(
        workspace,
        allowed,
        account.pw_uid,
    )

    ancestors = collect_ancestors(
        workspace,
        account.pw_uid,
    )

    sys.stdout.flush()
    sys.stderr.flush()

    child = os.fork()

    if child == 0:
        status = 1

        try:
            os.initgroups(account.pw_name, account.pw_gid)
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)

            if (
                os.getuid() != account.pw_uid
                or os.geteuid() != account.pw_uid
                or os.getgid() != account.pw_gid
                or os.getegid() != account.pw_gid
                or 0 in os.getgroups()
            ):
                raise BoundaryError(
                    "Build account privilege drop failed"
                )

            check_effective_access(
                entries,
                ancestors,
                allowed,
                account.pw_uid,
            )

            check_docker_socket_access()

            status = 0

        except Exception as exc:
            print(
                f"FAIL: {exc}",
                file=sys.stderr,
                flush=True,
            )

        finally:
            os._exit(status)

    _, status = os.waitpid(child, 0)

    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise BoundaryError(
            "Effective builder access verification failed"
        )

    print(
        f"PASS: Builder {user} "
        f"(UID {account.pw_uid}, GID {account.pw_gid})"
    )

    print(
        f"PASS: {len(entries)} protected entries and "
        f"{len(ancestors)} ancestors verified."
    )

    for path in sorted(allowed):
        print(f"PASS: Authorized writable workspace: {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("--user", required=True)
    parser.add_argument(
        "--workspace",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--writable",
        action="append",
        default=[],
    )

    args = parser.parse_args()

    try:
        verify(
            args.user,
            args.workspace,
            args.writable,
        )
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
