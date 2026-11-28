"""Single registry of approved package release-workflow contracts.

Package-specific builds remain in their respective publisher workflows.
This module contains no execution, signing, or publication authority.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class PackageContract:
    workflow: str
    validation_job: str
    recipe_style: str


CONTRACTS = {
    "engrampa": PackageContract(
        "publish-engrampa.yml",
        "Build and validate unsigned Engrampa", "fixed"),
    "mousepad": PackageContract(
        "publish-mousepad.yml",
        "Build and validate unsigned Mousepad", "fixed"),
    "thunar": PackageContract(
        "publish-thunar.yml",
        "Build and validate unsigned Thunar", "fixed"),
    "broot": PackageContract(
        "publish-broot.yml",
        "Build and validate unsigned Broot", "fixed"),
    "yazi": PackageContract(
        "publish-yazi.yml",
        "Build and validate unsigned Yazi", "fixed"),
    "gameshell": PackageContract(
        "publish-gameshell.yml",
        "Validate unsigned candidate", "generated"),
    "ghostty": PackageContract(
        "publish-ghostty.yml",
        "Build and validate unsigned Ghostty split packages", "fixed"),
    "keepassxc": PackageContract(
        "publish-keepassxc.yml",
        "Build and validate unsigned KeePassXC", "fixed"),
    "moonlight-qt": PackageContract(
        "publish-moonlight-qt.yml",
        "Build and validate unsigned Moonlight Qt", "fixed"),
    "noctalia-custom": PackageContract(
        "publish-noctalia-custom.yml",
        "Validate unsigned candidate", "generated"),
    "noctalia-greeter-t4t3z0r": PackageContract(
        "publish-noctalia-greeter.yml",
        "Validate unsigned candidate", "generated"),
    "syncthing": PackageContract(
        "publish-syncthing.yml",
        "Build and validate unsigned Syncthing", "fixed"),
    "wezterm": PackageContract(
        "publish-wezterm.yml",
        "Build and validate unsigned WezTerm pair", "fixed"),
}

SUPPORTED = tuple(CONTRACTS)

TEMPLATE_PACKAGES = frozenset(
    name for name, spec in CONTRACTS.items()
    if spec.recipe_style == "generated"
)

VALIDATION_JOBS = {
    name: spec.validation_job
    for name, spec in CONTRACTS.items()
}


def workflow_file(package):
    if package not in SUPPORTED:
        raise ValueError("Unsupported package")
    return CONTRACTS[package].workflow


@dataclass(frozen=True)
class PackageOutputContract:
    architecture: str
    required: tuple[str, ...]
    optional: tuple[str, ...] = ()
    debug_companions: tuple[
        tuple[str, tuple[str, ...]], ...
    ] = ()


def single_output(name, *, debug=False, architecture="x86_64"):
    debug_name = name + "-debug"

    return PackageOutputContract(
        architecture=architecture,
        required=(name,),
        optional=(debug_name,) if debug else (),
        debug_companions=(
            ((debug_name, (name,)),) if debug else ()
        ),
    )


OUTPUT_CONTRACTS = {
    "engrampa": single_output("engrampa", debug=True),
    "mousepad": single_output("mousepad", debug=True),
    "thunar": single_output("thunar", debug=True),
    "broot": single_output("broot", debug=True),
    "yazi": single_output("yazi", debug=True),
    "gameshell": single_output(
        "gameshell",
        architecture="any",
    ),
    "ghostty": PackageOutputContract(
        architecture="x86_64",
        required=(
            "ghostty",
            "ghostty-shell-integration",
            "ghostty-terminfo",
            "ghostty-nautilus",
        ),
        optional=("ghostty-debug",),
        debug_companions=(
            ("ghostty-debug", ("ghostty",)),
        ),
    ),
    "keepassxc": single_output(
        "keepassxc",
        debug=True,
    ),
    "moonlight-qt": single_output(
        "moonlight-qt",
        debug=True,
    ),
    "noctalia-custom": single_output(
        "noctalia-custom",
    ),
    "noctalia-greeter-t4t3z0r": single_output(
        "noctalia-greeter-t4t3z0r",
    ),
    "syncthing": PackageOutputContract(
        architecture="x86_64",
        required=(
            "syncthing",
            "syncthing-discosrv",
            "syncthing-relaysrv",
        ),
        optional=(
            "syncthing-debug",
            "syncthing-discosrv-debug",
            "syncthing-relaysrv-debug",
        ),
        debug_companions=(
            (
                "syncthing-debug",
                (
                    "syncthing",
                    "syncthing-discosrv",
                    "syncthing-relaysrv",
                ),
            ),
            (
                "syncthing-discosrv-debug",
                ("syncthing-discosrv",),
            ),
            (
                "syncthing-relaysrv-debug",
                ("syncthing-relaysrv",),
            ),
        ),
    ),
    "wezterm": PackageOutputContract(
        architecture="x86_64",
        required=("wezterm", "wezterm-debug"),
        debug_companions=(
            ("wezterm-debug", ("wezterm",)),
        ),
    ),
}


def output_contract(family):
    if family not in OUTPUT_CONTRACTS:
        raise ValueError("Unsupported package family")

    return OUTPUT_CONTRACTS[family]


def validate_output_names(family, names):
    contract = output_contract(family)
    names = tuple(names)

    if len(names) != len(set(names)):
        raise ValueError("Duplicate package output")

    actual = set(names)
    required = set(contract.required)
    allowed = required | set(contract.optional)

    missing = required - actual
    unexpected = actual - allowed

    if missing:
        raise ValueError(
            "Missing required package outputs: "
            + ", ".join(sorted(missing))
        )

    if unexpected:
        raise ValueError(
            "Unexpected package outputs: "
            + ", ".join(sorted(unexpected))
        )

    return contract


def validate_output_contracts():
    if set(OUTPUT_CONTRACTS) != set(CONTRACTS):
        raise ValueError(
            "Release and output contract families differ"
        )

    owners = {}

    for family, contract in OUTPUT_CONTRACTS.items():
        if contract.architecture not in {"any", "x86_64"}:
            raise ValueError(
                f"Unsupported architecture: {family}"
            )

        required = set(contract.required)
        optional = set(contract.optional)
        allowed = required | optional

        if (
            family not in required
            or required & optional
            or len(required) != len(contract.required)
            or len(optional) != len(contract.optional)
        ):
            raise ValueError(
                f"Invalid output membership: {family}"
            )

        for name in allowed:
            if name in owners:
                raise ValueError(
                    f"Duplicate output ownership: {name}"
                )

            owners[name] = family

        mappings = dict(contract.debug_companions)

        if len(mappings) != len(contract.debug_companions):
            raise ValueError(
                f"Duplicate debug relationship: {family}"
            )

        debug_outputs = {
            name for name in allowed
            if name.endswith("-debug")
        }

        if set(mappings) != debug_outputs:
            raise ValueError(
                f"Incomplete debug relationships: {family}"
            )

        for debug_name, companions in mappings.items():
            if (
                not companions
                or len(companions) != len(set(companions))
                or not set(companions) <= required
                or set(companions) & debug_outputs
            ):
                raise ValueError(
                    f"Invalid debug companions: {debug_name}"
                )


validate_output_contracts()
