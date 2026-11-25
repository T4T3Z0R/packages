"""Restricted stable XFCE Git source policy."""

import re
import subprocess

POLICY = "stable-xfce-git-tag"

UPSTREAMS = {
    "thunar": "https://gitlab.xfce.org/xfce/thunar.git",
    "mousepad": "https://gitlab.xfce.org/apps/mousepad.git",
}

TAGS = {
    package: re.compile(
        rf"{re.escape(package)}-([0-9]+)[.]([0-9]+)[.]([0-9]+)",
        re.ASCII,
    )
    for package in UPSTREAMS
}


def tag_pattern(package):
    if package not in TAGS:
        raise ValueError("Unsupported XFCE package")
    return TAGS[package]


def tag_package(tag):
    if not isinstance(tag, str):
        raise ValueError("Invalid XFCE source tag")

    for package, pattern in TAGS.items():
        if pattern.fullmatch(tag):
            return package

    raise ValueError("Invalid XFCE source tag")

SHA = re.compile(r"[0-9a-f]{40}", re.ASCII)


def stable_version(tag, package="thunar"):
    """Return the numeric stable version or reject the tag."""
    if not isinstance(tag, str):
        raise ValueError("Invalid XFCE source tag")

    match = tag_pattern(package).fullmatch(tag)

    if match is None:
        raise ValueError("Invalid XFCE source tag")

    parts = match.groups()

    if any(str(int(part)) != part for part in parts):
        raise ValueError("Noncanonical XFCE source version")

    # Thunar uses odd minor versions for development.
    # Mousepad does not follow that convention. Numeric Mousepad
    # candidates remain subject to human release review.
    if package == "thunar" and int(parts[1]) % 2:
        raise ValueError("XFCE development series is not stable")

    return ".".join(parts)


def validate_source(name, upstream, selected):
    if name not in UPSTREAMS or upstream != UPSTREAMS[name]:
        raise ValueError("Unsupported XFCE upstream repository")

    return stable_version(selected, name)


def latest_stable_tag(output, package="thunar"):
    """Parse native Git tag references without using a GitHub API."""
    versions = {}

    for line in output.splitlines():
        fields = line.split(chr(9))

        if len(fields) != 2:
            raise ValueError("Malformed XFCE Git reference")

        sha, ref = fields

        if not SHA.fullmatch(sha) or not ref.startswith("refs/tags/"):
            raise ValueError("Invalid XFCE Git reference")

        tag = ref.removeprefix("refs/tags/")

        try:
            version = stable_version(tag, package)
        except ValueError:
            continue

        if tag in versions:
            raise ValueError("Duplicate XFCE stable tag")

        versions[tag] = tuple(map(int, version.split(".")))

    if not versions:
        raise ValueError("No stable XFCE release tags")

    return max(versions, key=versions.__getitem__)


def discover(name, upstream, selected):
    validate_source(name, upstream, selected)

    # Do not inherit GitHub tokens, credential helpers, or Git
    # configuration when accessing the explicitly allowed public remote.
    result = subprocess.run(
        [
            "/usr/bin/git",
            "-c", "credential.helper=",
            "ls-remote", "--exit-code", "--tags", "--refs",
            upstream,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )

    return latest_stable_tag(result.stdout, name)
