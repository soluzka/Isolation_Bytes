"""
Self-hosted license manager -- no third-party dependency.

Features:
  - RSA-2048 signed license keys (offline-verifiable with public key)
  - Device/hardware locking (bind license to machine_id)
  - Tiered feature gating (Basic, Pro, Enterprise)
  - Activation tracking (limit number of devices per license)
  - Revocation
  - Persistent JSON storage

License key format:
  IB-<base64url(payload)>.<base64url(signature)>

  payload = JSON {
    "id":          "lic_...",      # unique license ID
    "tier":        "pro",          # basic | pro | enterprise
    "features":    ["yara","ml","quarantine","realtime","cloud_api"],
    "max_devices": 3,              # max simultaneous activations
    "issued_at":   1700000000,     # unix timestamp
    "expires_at":  0,              # 0 = never expires
    "customer":    "user@example.com"
  }
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


# ============================================================
# Tier definitions
# ============================================================

TIERS: Dict[str, Dict[str, Any]] = {
    "one_time": {
        "display_name": "One-Time Purchase",
        "features": ["yara", "ml", "quarantine", "dashboard", "cloud_api", "realtime"],
        "max_devices_default": 1,
        "price_hint": "$9.99",
        "expires": False,  # never expires
    },
    "subscription": {
        "display_name": "2-Year Subscription",
        "features": ["yara", "ml", "quarantine", "dashboard", "cloud_api", "realtime",
                      "priority_updates", "priority_support"],
        "max_devices_default": 3,
        "price_hint": "$10.00/2yr",
        "expires": True,  # expires every 2 years -- must be renewed
        "duration_days": 730,
    },
    "subscription_6mo": {
        "display_name": "6-Month Subscription",
        "features": ["yara", "ml", "quarantine", "dashboard", "cloud_api", "realtime",
                      "priority_updates", "priority_support"],
        "max_devices_default": 3,
        "price_hint": "$4.99/6mo",
        "expires": True,  # expires every 6 months -- must be renewed
        "duration_days": 180,
    },
}


def get_tier_features(tier: str) -> List[str]:
    """Return the feature list for a tier."""
    return TIERS.get(tier.lower(), TIERS["one_time"])["features"]


def get_tier_display_name(tier: str) -> str:
    return TIERS.get(tier.lower(), TIERS["one_time"])["display_name"]


# ============================================================
# Data classes
# ============================================================

@dataclass
class Activation:
    machine_id: str
    activated_at: int
    instance_name: str = ""


@dataclass
class LicenseRecord:
    license_id: str
    tier: str
    features: List[str]
    max_devices: int
    issued_at: int
    expires_at: int  # 0 = never
    customer: str
    revoked: bool = False
    activations: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LicenseRecord":
        return cls(
            license_id=d["license_id"],
            tier=d.get("tier", "one_time"),
            features=d.get("features", []),
            max_devices=d.get("max_devices", 1),
            issued_at=d.get("issued_at", 0),
            expires_at=d.get("expires_at", 0),
            customer=d.get("customer", ""),
            revoked=d.get("revoked", False),
            activations=d.get("activations", []),
        )


# ============================================================
# License Manager
# ============================================================

class LicenseManager:
    """Manages RSA key pair, license generation, validation, and activation."""

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self._private_key_path = self.data_dir / "license_private.pem"
        self._public_key_path = self.data_dir / "license_public.pem"
        self._store_path = self.data_dir / "licenses.json"

        self._private_key = None
        self._public_key = None
        self._store: Dict[str, Dict[str, Any]] = {}
        self._load_keys()
        self._load_store()

    # ---- Key management ----

    def _load_keys(self):
        """Load or generate the RSA key pair."""
        if self._private_key_path.exists() and self._public_key_path.exists():
            priv_data = self._private_key_path.read_bytes()
            self._private_key = serialization.load_pem_private_key(priv_data, password=None)
            pub_data = self._public_key_path.read_bytes()
            self._public_key = serialization.load_pem_public_key(pub_data)
        else:
            self._generate_keys()

    def _generate_keys(self):
        """Generate a new RSA-2048 key pair and save to disk."""
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._public_key = self._private_key.public_key()

        priv_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._private_key_path.write_bytes(priv_pem)
        self._public_key_path.write_bytes(pub_pem)

        # Set restrictive permissions on private key
        try:
            self._private_key_path.chmod(0o600)
        except Exception:
            pass  # Windows doesn't support Unix chmod the same way

    def get_public_key_pem(self) -> str:
        """Return the public key in PEM format (safe to share/embed in clients)."""
        return self._public_key_path.read_text(encoding="utf-8")

    # ---- Store management ----

    def _load_store(self):
        if self._store_path.exists():
            try:
                self._store = json.loads(self._store_path.read_text(encoding="utf-8"))
            except Exception:
                self._store = {}
        else:
            self._store = {}

    def _save_store(self):
        self._store_path.write_text(
            json.dumps(self._store, indent=2, default=str),
            encoding="utf-8",
        )

    # ---- License generation ----

    def generate_license(
        self,
        tier: str = "one_time",
        customer: str = "",
        max_devices: Optional[int] = None,
        expires_at: int = 0,  # 0 = never
        license_id: Optional[str] = None,
    ) -> Tuple[str, LicenseRecord]:
        """Generate a new signed license key.

        Returns (license_key_string, LicenseRecord).
        """
        tier = tier.lower()
        if tier not in TIERS:
            raise ValueError(f"Unknown tier: {tier}. Must be one of {list(TIERS.keys())}")

        features = get_tier_features(tier)
        if max_devices is None:
            max_devices = TIERS[tier]["max_devices_default"]

        lic_id = license_id or f"lic_{uuid.uuid4().hex[:16]}"
        issued_at = int(time.time())

        # Auto-set expiry for subscription tier (30 days from issue)
        if expires_at == 0 and TIERS[tier].get("expires", False):
            duration_days = TIERS[tier].get("duration_days", 30)
            expires_at = issued_at + (duration_days * 86400)

        payload = {
            "id": lic_id,
            "tier": tier,
            "features": features,
            "max_devices": max_devices,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "customer": customer,
        }

        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        signature = self._private_key.sign(
            payload_json.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("ascii")
        sig_b64 = base64.urlsafe_b64encode(signature).decode("ascii")
        license_key = f"IB-{payload_b64}.{sig_b64}"

        record = LicenseRecord(
            license_id=lic_id,
            tier=tier,
            features=features,
            max_devices=max_devices,
            issued_at=issued_at,
            expires_at=expires_at,
            customer=customer,
        )
        self._store[lic_id] = record.to_dict()
        self._save_store()

        return license_key, record

    # ---- License validation ----

    def parse_license_key(self, license_key: str) -> Optional[Dict[str, Any]]:
        """Parse and verify the signature of a license key.

        Returns the payload dict if valid, None if the signature is invalid.
        Does NOT check expiry, revocation, or activation -- use validate_license()
        for full validation.
        """
        key = license_key.strip()
        if not key.startswith("IB-"):
            return None

        try:
            body = key[3:]
            payload_b64, sig_b64 = body.rsplit(".", 1)
            payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
            signature = base64.urlsafe_b64decode(sig_b64)

            self._public_key.verify(
                signature,
                payload_json.encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return json.loads(payload_json)
        except (InvalidSignature, ValueError, Exception):
            return None

    def validate_license(
        self,
        license_key: str,
        machine_id: str = "",
        require_activation: bool = False,
    ) -> Dict[str, Any]:
        """Full license validation.

        Returns a dict with:
          - valid: bool
          - error: str (if invalid)
          - license_id, tier, features, expires_at, customer
          - activated: bool
          - activations_used: int
        """
        payload = self.parse_license_key(license_key)
        if payload is None:
            return {"valid": False, "error": "Invalid license key format or signature"}

        lic_id = payload["id"]

        # Check revocation
        record = self._store.get(lic_id)
        if record and record.get("revoked", False):
            return {"valid": False, "error": "License has been revoked", "license_id": lic_id}

        # Check expiry
        expires_at = payload.get("expires_at", 0)
        if expires_at and expires_at > 0 and time.time() > expires_at:
            return {
                "valid": False,
                "error": "License has expired",
                "license_id": lic_id,
                "expires_at": expires_at,
            }

        # Check device activation
        activations = record.get("activations", []) if record else []
        activated = any(a.get("machine_id") == machine_id for a in activations) if machine_id else False

        if require_activation and machine_id and not activated:
            return {
                "valid": False,
                "error": "License is not activated for this device",
                "license_id": lic_id,
            }

        return {
            "valid": True,
            "license_id": lic_id,
            "tier": payload.get("tier", "one_time"),
            "features": payload.get("features", []),
            "max_devices": payload.get("max_devices", 1),
            "issued_at": payload.get("issued_at", 0),
            "expires_at": expires_at,
            "customer": payload.get("customer", ""),
            "activated": activated,
            "activations_used": len(activations),
        }

    # ---- Activation management ----

    def activate_license(
        self,
        license_key: str,
        machine_id: str,
        instance_name: str = "",
    ) -> Dict[str, Any]:
        """Activate a license for a specific device.

        Returns dict with:
          - ok: bool
          - error: str (if failed)
          - activation info
        """
        if not machine_id:
            return {"ok": False, "error": "Machine ID is required"}

        payload = self.parse_license_key(license_key)
        if payload is None:
            return {"ok": False, "error": "Invalid license key"}

        lic_id = payload["id"]

        # Check revocation/expiry
        validation = self.validate_license(license_key, machine_id)
        if not validation["valid"]:
            return {"ok": False, "error": validation["error"]}

        record = self._store.get(lic_id)
        if not record:
            # Create record from payload if it doesn't exist
            record = LicenseRecord(
                license_id=lic_id,
                tier=payload.get("tier", "one_time"),
                features=payload.get("features", []),
                max_devices=payload.get("max_devices", 1),
                issued_at=payload.get("issued_at", 0),
                expires_at=payload.get("expires_at", 0),
                customer=payload.get("customer", ""),
            ).to_dict()
            self._store[lic_id] = record

        activations = record.get("activations", [])

        # Already activated for this machine?
        for a in activations:
            if a.get("machine_id") == machine_id:
                return {
                    "ok": True,
                    "already_activated": True,
                    "license_id": lic_id,
                    "machine_id": machine_id,
                    "activations_used": len(activations),
                    "max_devices": payload.get("max_devices", 1),
                }

        # Check activation limit
        max_devices = payload.get("max_devices", 1)
        if len(activations) >= max_devices:
            return {
                "ok": False,
                "error": f"Activation limit reached ({max_devices} device(s)). "
                         f"Deactivate a device first.",
                "activations_used": len(activations),
                "max_devices": max_devices,
            }

        # Activate
        activation = {
            "machine_id": machine_id,
            "activated_at": int(time.time()),
            "instance_name": instance_name or machine_id,
        }
        activations.append(activation)
        record["activations"] = activations
        self._store[lic_id] = record
        self._save_store()

        return {
            "ok": True,
            "already_activated": False,
            "license_id": lic_id,
            "machine_id": machine_id,
            "activations_used": len(activations),
            "max_devices": max_devices,
            "tier": payload.get("tier", "one_time"),
            "features": payload.get("features", []),
            "expires_at": payload.get("expires_at", 0),
        }

    def deactivate_license(
        self,
        license_key: str,
        machine_id: str,
    ) -> Dict[str, Any]:
        """Deactivate a license for a specific device."""
        payload = self.parse_license_key(license_key)
        if payload is None:
            return {"ok": False, "error": "Invalid license key"}

        lic_id = payload["id"]
        record = self._store.get(lic_id)
        if not record:
            return {"ok": False, "error": "License not found in store"}

        activations = record.get("activations", [])
        new_activations = [a for a in activations if a.get("machine_id") != machine_id]

        if len(new_activations) == len(activations):
            return {"ok": False, "error": "Device was not activated"}

        record["activations"] = new_activations
        self._store[lic_id] = record
        self._save_store()

        return {
            "ok": True,
            "license_id": lic_id,
            "machine_id": machine_id,
            "activations_used": len(new_activations),
        }

    # ---- Admin operations ----

    def list_licenses(self) -> List[Dict[str, Any]]:
        """List all licenses in the store."""
        result = []
        for lic_id, record in self._store.items():
            entry = dict(record)
            entry["activations_count"] = len(record.get("activations", []))
            # Don't expose full activation details in list view
            entry["activations"] = [
                {"machine_id": a.get("machine_id", ""),
                 "activated_at": a.get("activated_at", 0),
                 "instance_name": a.get("instance_name", "")}
                for a in record.get("activations", [])
            ]
            result.append(entry)
        return result

    def revoke_license(self, license_id: str) -> Dict[str, Any]:
        """Revoke a license by its ID."""
        record = self._store.get(license_id)
        if not record:
            return {"ok": False, "error": "License not found"}
        record["revoked"] = True
        self._store[license_id] = record
        self._save_store()
        return {"ok": True, "license_id": license_id}

    def unrevoke_license(self, license_id: str) -> Dict[str, Any]:
        """Un-revoke a license."""
        record = self._store.get(license_id)
        if not record:
            return {"ok": False, "error": "License not found"}
        record["revoked"] = False
        self._store[license_id] = record
        self._save_store()
        return {"ok": True, "license_id": license_id}

    def delete_license(self, license_id: str) -> Dict[str, Any]:
        """Permanently delete a license from the store."""
        if license_id not in self._store:
            return {"ok": False, "error": "License not found"}
        del self._store[license_id]
        self._save_store()
        return {"ok": True, "license_id": license_id}

    def get_license_info(self, license_id: str) -> Optional[Dict[str, Any]]:
        """Get full info for a single license."""
        return self._store.get(license_id)

    # ---- Feature checking ----

    def has_feature(self, license_key: str, feature: str, machine_id: str = "") -> bool:
        """Check if a license grants a specific feature."""
        validation = self.validate_license(license_key, machine_id)
        if not validation["valid"]:
            return False
        return feature in validation.get("features", [])


# ============================================================
# Machine ID generation (for clients)
# ============================================================

def generate_machine_id() -> str:
    """Generate a random machine ID for web clients."""
    return f"web_{secrets.token_hex(12)}"


def hash_machine_id(machine_id: str) -> str:
    """Hash a machine ID for storage/lookup (one-way)."""
    return hashlib.sha256(machine_id.encode("utf-8")).hexdigest()[:32]

