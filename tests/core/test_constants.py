import dataclasses

import pytest

from zk_age_verifier.core.constants import DOC_TYPE, EU_AV, ISO_MDL, PROFILES, CredentialProfile


def test_profiles_are_keyed_by_their_names() -> None:
    assert PROFILES == {"eu-av": EU_AV, "iso-mdl": ISO_MDL}
    assert all(name == profile.name for name, profile in PROFILES.items())


def test_eu_av_uses_one_string_for_doctype_and_namespace() -> None:
    assert EU_AV.doc_type == EU_AV.namespace == "eu.europa.ec.av.1"


def test_iso_mdl_keeps_doctype_and_namespace_apart() -> None:
    assert ISO_MDL.doc_type == "org.iso.18013.5.1.mDL"
    assert ISO_MDL.namespace == "org.iso.18013.5.1"


def test_the_module_level_doctype_is_the_default_profile() -> None:
    assert DOC_TYPE == EU_AV.doc_type


def test_a_profile_cannot_be_changed() -> None:
    attribute = "namespace"
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(EU_AV, attribute, "elsewhere")
    assert isinstance(EU_AV, CredentialProfile)
