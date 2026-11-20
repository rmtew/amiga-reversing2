"""Pinned authorized FoFT host inputs; not an executable runtime recipe."""

from .original_media_preflight import FileIdentity, InputContract, SourceIdentity

CONTRACT = InputContract(
    target="amiga_raw_foft",
    media=(
        (
            "game-disc",
            FileIdentity(
                995846,
                ("da33fc1e068d73078094fc4cb6f72ab69a9c2f30f4094b8321033aedb6237b93",),
            ),
        ),
    ),
    rom=FileIdentity(
        524288, ("1d68ba18412501d2a4b307a0a632b94a50b839c2c7c5ff2df6de2c38b99a921f",)
    ),
    runtime=FileIdentity(
        None,
        (
            "9ab3e2ecc89beb25344bd1b0d8aa3dcf9370ade8f3b08fdec2fb37e59461f55d",
            "e92e5d527369ae7565e8d8b16f978da7c6868f41aa4b0d8e01a9e7f4956eea3c",
        ),
    ),
    sources=(
        SourceIdentity(
            "boot",
            4000,
            "b52575d366313c1648976925c368e7a990d30477e7a099301dcabb031a3939a1",
            0x78000,
            "pre_handoff",
        ),
        SourceIdentity(
            "main",
            489472,
            "85e2684b03badc7308e7eaa059b7c717441808798f55b4642e1d8b1895914c9b",
            0x800,
            "handoff",
        ),
    ),
)
