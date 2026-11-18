# Release steps

The steps that have to happen before a tag, in the order they have to happen
in. Publishing itself is manual and stays that way; what is written down here
is only what a tag is allowed to be cut on top of.

## 1. Bump the version in both places

`pyproject.toml` (`version`) and `misp_stix_converter/__init__.py`
(`__version__`) carry the same number, and
`tests/test_public_surface.py::test_version_matches_the_packaging_metadata`
fails if they drift. One commit, both files - `d646d09d` is the shape.

## 2. Check the MISP Extensions against the Common Object Repository

    python3 tools/update_misp_extensions.py --check

The OASIS Common Object Repository (`oasis-open/cti-stix-common-objects`) is
the canonical home of the MISP Extensions: the definitions every STIX 2.1
bundle embeds, and the suite under `data/misp-extensions/`, are copies synced
from its `main`. The check writes nothing; it lists what differs and exits 1
when the copy is behind. When it is, run the script without `--check`, put
what it reports changed in the definitions into the release notes, and commit
the sync: the suite of step 3 runs against it.

## 3. Run the whole suite

    poetry run pytest tests/test_*.py -q -p no:warnings

This is what CI runs on every push to `main` and `dev`, across Python
3.10-3.14. The two wheel tests report as skipped here; step 4 is what runs
them.

## 4. Build the wheel and run it

    MISP_STIX_WHEEL_TESTS=1 poetry run pytest tests/test_wheel_contents.py

`poetry build` sweeps the package *directory*, not git, so the wheel carries
whatever is sitting under `misp_stix_converter/` at build time. This step
builds a wheel, reads its inventory, installs it somewhere it shadows the
source tree, and converts one event through the installed copy - which also
proves `data/cti_uuid_catalog.json` shipped.

It is not in CI on purpose: CI runs on push, the upload happens by hand
afterwards, and a test that runs after publication protects nothing. Run it
here, before the tag.

What it cannot tell you: it installs with `--no-deps` so that it works
offline, so a wrong or missing dependency declaration in `pyproject.toml`
passes it. Read the dependency table yourself when it changed.

## 5. Tag, then upload

Both by hand, in that order.
