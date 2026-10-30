from dataclasses import dataclass
from pathlib import Path

SAMPLES_DIRECTORY = Path(__file__).parent


@dataclass(frozen=True)
class SampleDefinition:
    name: str
    title: str
    description: str
    filename: str


SAMPLES: dict[str, SampleDefinition] = {
    "acme-prod": SampleDefinition(
        name="acme-prod",
        title="Acme production",
        description=(
            "Nine identities and six resources with an admin user, a role chain, "
            "a cross-account trust, a public bucket and an explicit deny."
        ),
        filename="acme_prod.json",
    ),
    "acme-dev": SampleDefinition(
        name="acme-dev",
        title="Acme development",
        description="A small development account with narrowly scoped access and no sensitive resources.",
        filename="acme_dev.json",
    ),
}


def list_samples() -> list[SampleDefinition]:
    return list(SAMPLES.values())


def read_sample(name: str) -> bytes | None:
    definition = SAMPLES.get(name)
    if definition is None:
        return None
    return (SAMPLES_DIRECTORY / definition.filename).read_bytes()