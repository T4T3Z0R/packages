"""Native qualification of static ELF dependency resolution."""

import hashlib
import os
import shutil
import subprocess
import tempfile

from pathlib import Path


ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "HOME": "/tmp",
}


def run(arguments, *, check=True, cwd=None):
    return subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        env=ENVIRONMENT,
        cwd=cwd,
        check=check,
    )


def report(label, arguments, *, cwd=None):
    result = run(
        arguments,
        check=False,
        cwd=cwd,
    )

    print(f"\n=== {label} ===")
    print(f"Exit status: {result.returncode}")
    print("--- stdout ---")
    print(result.stdout.rstrip())
    print("--- stderr ---")
    print(result.stderr.rstrip())

    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if os.getuid() == 0 or os.geteuid() == 0:
        raise RuntimeError(
            "Resolver qualification must run unprivileged"
        )

    print("=== QUALIFICATION PROCESS IDENTITY ===")

    print(run(["/usr/bin/id"]).stdout.rstrip())

    status = Path("/proc/self/status").read_text()

    for line in status.splitlines():
        if line.startswith((
            "Uid:", "Gid:", "Groups:",
            "CapInh:", "CapPrm:", "CapEff:",
            "CapBnd:", "CapAmb:", "NoNewPrivs:",
        )):
            print(line)

    for field in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        records = [
            line.split(":", 1)[1].strip()
            for line in status.splitlines()
            if line.startswith(field + ":")
        ]

        if len(records) != 1 or int(records[0], 16) != 0:
            raise RuntimeError(
                f"Unexpected process capabilities: {field}"
            )

    if (
        len(set(os.getresuid())) != 1
        or len(set(os.getresgid())) != 1
        or 0 in os.getresuid()
        or 0 in os.getresgid()
        or 0 in os.getgroups()
    ):
        raise RuntimeError("Unexpected privileged identity")

    tools = {}

    for name in ("cc", "readelf", "lddtree", "python"):
        path = shutil.which(name)

        if path is None:
            raise RuntimeError(f"Missing required tool: {name}")

        tools[name] = path

        print(f"{name}: {path}")

    report(
        "STATIC RESOLVER HELP",
        [tools["lddtree"], "--help"],
    )

    report(
        "STATIC RESOLVER VERSION",
        [tools["lddtree"], "--version"],
    )

    print("\n=== INSTALLED RESOLVER PACKAGES ===")

    print(run([
        "/usr/bin/pacman", "-Q",
        "pax-utils", "python-pyelftools",
        "glibc", "binutils",
    ]).stdout.rstrip())

    resolver = Path(tools["lddtree"]).resolve()

    print(f"Resolver path: {resolver}")
    print(f"Resolver SHA256: {digest(resolver)}")

    report(
        "TRUSTED SYSTEM ELF",
        [tools["lddtree"], "/usr/bin/bash"],
    )

    with tempfile.TemporaryDirectory(
        prefix="static-linkage-qualification-"
    ) as scratch:

        root = Path(scratch)

        leaf = root / "libleaf_w01b2.so"
        middle = root / "libmiddle_w01b2.so"
        binary = root / "fixture"

        (root / "leaf.c").write_text(
            "int leaf(void) { return 7; }\n"
        )

        (root / "middle.c").write_text(
            "extern int leaf(void);\n"
            "int middle(void) { return leaf(); }\n"
        )

        (root / "main.c").write_text(
            "#include <stdio.h>\n"
            "extern int middle(void);\n"
            "int main(void) {\n"
            '    FILE *f = fopen("execution-marker", "w");\n'
            "    if (f) fclose(f);\n"
            "    return middle();\n"
            "}\n"
        )

        cc = tools["cc"]

        run([
            cc, "-shared", "-fPIC",
            "-Wl,-soname,libleaf_w01b2.so",
            "-o", str(leaf),
            str(root / "leaf.c"),
        ])

        run([
            cc, "-shared", "-fPIC",
            "-Wl,-soname,libmiddle_w01b2.so",
            "-Wl,-rpath,$ORIGIN",
            "-o", str(middle),
            str(root / "middle.c"),
            "-L" + str(root),
            "-lleaf_w01b2",
        ])

        run([
            cc,
            "-Wl,-rpath,$ORIGIN",
            "-Wl,-rpath-link," + str(root),
            "-o", str(binary),
            str(root / "main.c"),
            "-L" + str(root),
            "-lmiddle_w01b2",
        ])

        before = {
            path.name: digest(path)
            for path in (leaf, middle, binary)
        }

        for path in (leaf, middle, binary):
            report(
                f"ELF DYNAMIC METADATA: {path.name}",
                [tools["readelf"], "-dW", "--", str(path)],
                cwd=root,
            )

        complete = report(
            "COMPLETE DIRECT AND TRANSITIVE DEPENDENCIES",
            [tools["lddtree"], str(binary)],
            cwd=root,
        )

        hidden_leaf = root / "leaf.hidden"
        leaf.rename(hidden_leaf)

        try:
            missing_transitive = report(
                "MISSING TRANSITIVE DEPENDENCY",
                [tools["lddtree"], str(binary)],
                cwd=root,
            )
        finally:
            hidden_leaf.rename(leaf)

        hidden_middle = root / "middle.hidden"
        middle.rename(hidden_middle)

        try:
            missing_direct = report(
                "MISSING DIRECT DEPENDENCY",
                [tools["lddtree"], str(binary)],
                cwd=root,
            )
        finally:
            hidden_middle.rename(middle)

        report(
            "LIST MODE",
            [tools["lddtree"], "-l", str(binary)],
            cwd=root,
        )

        report(
            "NONEXISTENT INPUT",
            [tools["lddtree"], str(root / "missing")],
            cwd=root,
        )

        invalid = root / "invalid"
        invalid.write_bytes(b"not an ELF file\n")

        report(
            "NON-ELF INPUT",
            [tools["lddtree"], str(invalid)],
            cwd=root,
        )

        print("\n=== QUALIFICATION INVARIANTS ===")

        if complete.returncode != 0:
            raise RuntimeError(
                "Complete dependency fixture failed"
            )

        for expected in (str(leaf), str(middle)):
            if expected not in complete.stdout:
                raise RuntimeError(
                    f"Complete fixture did not resolve {expected}"
                )

        if "libleaf_w01b2.so" not in (
            missing_transitive.stdout
            + missing_transitive.stderr
        ):
            raise RuntimeError(
                "Transitive dependency absent from report"
            )

        if "libmiddle_w01b2.so" not in (
            missing_direct.stdout
            + missing_direct.stderr
        ):
            raise RuntimeError(
                "Direct dependency absent from report"
            )

        if (root / "execution-marker").exists():
            raise RuntimeError(
                "Unexpected candidate program execution"
            )

        after = {
            path.name: digest(path)
            for path in (leaf, middle, binary)
        }

        if before != after:
            raise RuntimeError(
                "Resolver modified fixture contents"
            )

        print("PASS: Complete dependency fixture resolved.")
        print("PASS: Missing dependency behavior recorded.")
        print("PASS: Candidate main function not executed.")
        print("PASS: Fixture bytes unchanged.")

    print("\nPASS: Native static resolver qualification completed.")


if __name__ == "__main__":
    main()
