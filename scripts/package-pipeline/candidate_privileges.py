"""Linux process privilege restrictions for candidate inspection."""

import os
import re

from pathlib import Path


class PrivilegeError(RuntimeError):
    """Candidate inspection process is insufficiently restricted."""


CAPABILITY_FIELDS = (
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
)

REQUIRED_FIELDS = frozenset({
    "Uid",
    "Gid",
    "Groups",
    "NoNewPrivs",
    *CAPABILITY_FIELDS,
})


def validate_process_status(status, *, uid, gid):
    """Validate real, effective, saved and filesystem identities."""

    if (
        type(uid) is not int
        or type(gid) is not int
        or uid <= 0
        or gid <= 0
    ):
        raise PrivilegeError("Invalid unprivileged identity")

    fields = {}

    for line in status.splitlines():
        name, separator, value = line.partition(":")

        if not separator or name not in REQUIRED_FIELDS:
            continue

        if name in fields:
            raise PrivilegeError(
                f"Duplicate process status field: {name}"
            )

        fields[name] = value.strip()

    if set(fields) != REQUIRED_FIELDS:
        raise PrivilegeError(
            "Required process privilege fields missing"
        )

    for field, expected in (
        ("Uid", uid),
        ("Gid", gid),
    ):
        values = fields[field].split()

        if (
            len(values) != 4
            or any(
                re.fullmatch(r"[0-9]+", value) is None
                for value in values
            )
            or any(
                int(value) != expected
                for value in values
            )
        ):
            raise PrivilegeError(
                f"Unexpected process identity: {field}"
            )

    if fields["Groups"]:
        raise PrivilegeError(
            "Supplementary groups must be empty"
        )

    for field in CAPABILITY_FIELDS:
        value = fields[field]

        if (
            re.fullmatch(r"[0-9a-fA-F]{16}", value) is None
            or int(value, 16) != 0
        ):
            raise PrivilegeError(
                f"Nonzero or invalid capability set: {field}"
            )

    if fields["NoNewPrivs"] != "1":
        raise PrivilegeError(
            "NoNewPrivs must be enabled"
        )

    return {
        "uid": uid,
        "gid": gid,
        "supplementary_groups": [],
        "capabilities_cleared": True,
        "bounding_set_cleared": True,
        "no_new_privs": True,
    }


def require_inspection_identity():
    """Reject execution outside the qualified privilege boundary."""

    uids = os.getresuid()
    gids = os.getresgid()

    if (
        len(set(uids)) != 1
        or len(set(gids)) != 1
        or 0 in uids
        or 0 in gids
        or os.getgroups()
    ):
        raise PrivilegeError(
            "Unexpected process identity or supplementary groups"
        )

    return validate_process_status(
        Path("/proc/self/status").read_text(
            encoding="ascii"
        ),
        uid=uids[0],
        gid=gids[0],
    )
