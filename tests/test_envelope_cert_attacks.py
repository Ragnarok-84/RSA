"""Ký tệp thật, chứng thư số mini và các kịch bản tấn công."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from rsasig.attacks.demos import DEMOS, pollard_rho
from rsasig.core.certificate import issue_certificate, verify_certificate
from rsasig.core.envelope import sign_file, verify_file


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "hop_dong.txt"
    p.write_text("Bên A bán cho Bên B 10 tấn cà phê, tổng 1.200.000.000 VND.", encoding="utf-8")
    return p


@pytest.mark.parametrize("scheme", ["pss", "pkcs1v15"])
def test_file_sign_verify(key1024, sample, scheme):
    env = sign_file(key1024, sample, "Alice", scheme)
    assert verify_file(key1024.public_key(), sample, env).valid


def test_binary_file(key1024, tmp_path):
    p = tmp_path / "img.bin"
    p.write_bytes(bytes(range(256)) * 400)
    env = sign_file(key1024, p, "Alice")
    assert verify_file(key1024.public_key(), p, env).valid


def test_file_modified_detected(key1024, sample):
    env = sign_file(key1024, sample, "Alice")
    sample.write_text(sample.read_text(encoding="utf-8").replace("1.200", "1.000"), encoding="utf-8")
    result = verify_file(key1024.public_key(), sample, env)
    assert not result.valid and not result.checks[0][1]


def test_manifest_signer_changed_detected(key1024, sample):
    env = sign_file(key1024, sample, "Alice")
    forged = json.loads(json.dumps(env))
    forged["manifest"]["signer"] = "Bob"
    assert not verify_file(key1024.public_key(), sample, forged).valid


def test_wrong_key_detected(key1024, other_key, sample):
    env = sign_file(key1024, sample, "Alice")
    assert not verify_file(other_key.public_key(), sample, env).valid


def test_certificate_valid_tampered_expired_revoked(key1024, other_key):
    ca, alice = key1024, other_key
    cert = issue_certificate(ca, "Demo-CA", "Alice", alice.public_key(), valid_days=30, serial=7)
    assert verify_certificate(ca.public_key(), cert)[0]

    tampered = json.loads(json.dumps(cert))
    tampered["tbs"]["subject"] = "Mallory"
    assert not verify_certificate(ca.public_key(), tampered)[0]

    future = datetime.now(timezone.utc) + timedelta(days=60)
    assert not verify_certificate(ca.public_key(), cert, at=future)[0]
    assert not verify_certificate(ca.public_key(), cert, revoked_serials={7})[0]


def test_pollard_rho():
    n = 1_000_003 * 999_983
    f = pollard_rho(n)
    assert f in (1_000_003, 999_983)


@pytest.mark.parametrize("name", list(DEMOS))
def test_attack_demos_match_theory(name):
    result = DEMOS[name]()
    assert result.as_expected, result.text()
