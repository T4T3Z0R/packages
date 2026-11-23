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
    "gameshell": PackageContract(
        "publish-gameshell.yml",
        "Validate unsigned candidate", "generated"),
    "ghostty": PackageContract(
        "publish-ghostty.yml",
        "Build and validate unsigned Ghostty split packages", "fixed"),
    "keepassxc": PackageContract(
        "publish-keepassxc.yml",
        "Build and validate unsigned KeePassXC", "fixed"),
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
