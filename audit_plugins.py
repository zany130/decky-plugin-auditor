#!/usr/bin/env python3
"""Compatibility entry point for the Decky plugin security audit.

The implementation remains in :mod:`audit_plugins_core`; context-aware noise,
network-destination, exact-source dependency, Semgrep, content-comparison,
source-mapping hardening, exact metadata build-stamp, behavioral false-positive,
credential-exposure, packaged-artifact, source-link, reviewer-capability, and
report-layout policies are installed before the module is exposed to callers or
the CLI runs.
"""

from __future__ import annotations

import sys

import audit_plugins_core as _core
import semgrep_source_scanning as _semgrep_source_scanning
from artifact_diff_filters import install as install_artifact_diff_filters
from audit_noise_filters import install as install_noise_filters
from behavior_false_positive_filters import install as install_behavior_filters
from credential_exposure_filters import install as install_credential_policy
from metadata_build_stamp_filters import install as install_metadata_build_stamp_filters
from network_destination_filters import install as install_network_destination_filters
from packaged_resources import resolve_distribution_file
from report_layout_filters import install as install_report_layout
from reviewer_capability_source_hardening import install as install_reviewer_source_hardening
from reviewer_capability_summaries import install as install_reviewer_capabilities
from semgrep_source_link_hardening import install as install_semgrep_link_hardening
from semgrep_source_scanning import install as install_semgrep_source_scanning
from source_content_comparison import install as install_source_content_comparison
from source_content_hardening import install as install_source_content_hardening
from trivy_source_scanning import install as install_trivy_source_scanning
from upstream_source_links import install as install_source_links

# Source checkouts keep the local rules beside the module. Installed wheels
# resolve the same file through distribution metadata before Semgrep runs.
_semgrep_source_scanning._SEMGREP_RULES_FILE = str(
    resolve_distribution_file(
        "semgrep-rules.yml",
        _semgrep_source_scanning.__file__,
    )
)

install_noise_filters(_core)
install_network_destination_filters(_core)
install_trivy_source_scanning(_core)
install_source_content_comparison(_core)
install_source_content_hardening(_core)
install_semgrep_source_scanning(_core)
install_metadata_build_stamp_filters(_core)
install_behavior_filters(_core)
install_credential_policy(_core)
install_artifact_diff_filters(_core)
install_source_links(_core)
install_semgrep_link_hardening(_core)
install_reviewer_capabilities(_core)
install_reviewer_source_hardening(_core)
install_report_layout(_core)

if __name__ == "__main__":
    raise SystemExit(_core.main())

# Preserve the historical import surface and, importantly, ensure mocks such as
# patch("audit_plugins._gh_get") modify the globals used by core functions.
sys.modules[__name__] = _core
