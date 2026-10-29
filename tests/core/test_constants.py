import dataclasses

import pytest

from zk_age_verifier.core.constants import (
    DOC_TYPE,
    EU_AV,
    GOOGLE_ID_PASS,
    ISO_MDL,
    PHOTO_ID,
    PROFILES,
    CredentialProfile,
)


def test_profiles_are_keyed_by_their_names() -> None:
    assert PROFILES == {
        "eu-av": EU_AV,
        "iso-mdl": ISO_MDL,
        "photo-id": PHOTO_ID,
        "google-id-pass": GOOGLE_ID_PASS,
    }
    assert all(name == profile.name for name, profile in PROFILES.items())


def test_eu_av_uses_one_string_for_doctype_and_namespace() -> None:
    assert EU_AV.doc_type == EU_AV.namespace == "eu.europa.ec.av.1"


def test_iso_mdl_keeps_doctype_and_namespace_apart() -> None:
    assert ISO_MDL.doc_type == "org.iso.18013.5.1.mDL"
    assert ISO_MDL.namespace == "org.iso.18013.5.1"


def test_passport_derived_profiles_name_their_doctype_and_namespace() -> None:
    # Values as in Multipaz's document types (PhotoID.kt, IDPass.kt).
    assert (PHOTO_ID.doc_type, PHOTO_ID.namespace) == ("org.iso.23220.photoid.1", "org.iso.23220.1")
    assert (GOOGLE_ID_PASS.doc_type, GOOGLE_ID_PASS.namespace) == (
        "com.google.wallet.idcard.1",
        "org.iso.18013.5.1",
    )


def test_every_doctype_is_different() -> None:
    # The verifier picks the profile from the response doctype, so none may repeat.
    doc_types = [profile.doc_type for profile in PROFILES.values()]
    assert len(set(doc_types)) == len(doc_types)


def test_the_module_level_doctype_is_the_default_profile() -> None:
    assert DOC_TYPE == EU_AV.doc_type


def test_a_profile_cannot_be_changed() -> None:
    attribute = "namespace"
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(EU_AV, attribute, "elsewhere")
    assert isinstance(EU_AV, CredentialProfile)
