"""
Stage 8 — Deployment topology.

Regions (order matters — leader-region attribution uses this ordering):
    virginia   — us-east-1
    ireland    — eu-west-1
    tokyo      — ap-northeast-1
    sydney     — ap-southeast-2
    mumbai     — ap-south-1

Validator layout: 48 total, distributed by validator_count_per_region.
For the reviewer's 4-region minimum:
    virginia:12, ireland:12, tokyo:12, sydney:12 = 48

For the 5-region full deployment (uses Stage-7 topology):
    virginia:21, ireland:7, tokyo:7, sydney:7, mumbai:6 = 48
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from leader_selection import StakeSnapshot


CHAIN_ID_DEFAULT = b"FAIRNESS_WITNESS_V1"

# The reviewer's 4-region minimum with equal validators per region
DEPLOYMENT_4_REGION = {
    "virginia": 12,
    "ireland":  12,
    "tokyo":    12,
    "sydney":   12,
}

# The Stage-7 5-region topology (used if you deploy all 5 regions)
DEPLOYMENT_5_REGION = {
    "virginia": 21,
    "ireland":   7,
    "tokyo":     7,
    "sydney":    7,
    "mumbai":    6,
}

# Static port allocation for coordination
DEFAULT_LISTEN_PORT = 15078
DEFAULT_MASTER_PORT = 15079


@dataclass(frozen=True)
class Stage8Validator:
    validator_id: int
    region: str
    stake: int = 1


def build_topology(deployment: Dict[str, int]) -> List[Stage8Validator]:
    """Emit validators in deterministic order."""
    validators: List[Stage8Validator] = []
    vid = 0
    for region, count in deployment.items():
        for _ in range(count):
            validators.append(Stage8Validator(vid, region))
            vid += 1
    if sum(deployment.values()) != len(validators):
        raise RuntimeError("bad topology count")
    return validators


def build_stage8_snapshot(validators: List[Stage8Validator]
                             ) -> Tuple[StakeSnapshot, List[Ed25519PrivateKey], List[bytes]]:
    """Deterministic keys derived from validator ids."""
    sks, pks = [], []
    entries = []
    for v in validators:
        sk = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(f"stage8-validator:{v.validator_id}".encode()).digest())
        pk = sk.public_key().public_bytes_raw()
        sks.append(sk); pks.append(pk)
        entries.append({"validator_id": v.validator_id,
                          "public_key": pk,
                          "stake": v.stake})
    return StakeSnapshot(entries), sks, pks


def region_of_validator(vid: int, validators: List[Stage8Validator]) -> str:
    return validators[vid].region


def validators_in_region(region: str,
                           validators: List[Stage8Validator]) -> List[Stage8Validator]:
    return [v for v in validators if v.region == region]


@dataclass(frozen=True)
class RegionEndpoint:
    region: str
    host: str            # public/private IP or hostname
    port: int = DEFAULT_LISTEN_PORT


@dataclass(frozen=True)
class CampaignConfig:
    """A named campaign configuration."""
    name: str
    T_vdf: int               # Wesolowski difficulty parameter
    rounds: int
    warmup_rounds: int
    injected_delay_ms: float = 0.0   # optional extra sleep per phase
    committee_of_7: bool = True       # True: keep n=7 quorum semantics; False: n=48


def load_endpoints(path: str) -> List[RegionEndpoint]:
    """Load region endpoints from JSON file:
    {"regions": [{"region":"virginia","host":"...","port":15078}, ...]}
    """
    with open(path) as f:
        data = json.load(f)
    return [RegionEndpoint(**e) for e in data["regions"]]


def canonical_pair_key(a: str, b: str) -> Tuple[str, str]:
    return (a, b) if a <= b else (b, a)
