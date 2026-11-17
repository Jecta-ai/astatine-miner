# Frozen blocked-gate regression fixtures

These are byte-for-byte copies from base commit
`0ad7b957a04de65714209142576566be3d4de801` of the v1 blocked provenance and
distribution inventory, plus the original blocked fixture README and provenance metadata. The
byte-identical fixture JSONs and OpenZeppelin license are copied from the live
`tests/fixtures` tree at test runtime, avoiding duplicate bytecode here. These
fixtures exist only so the original 49 blocked-state distribution verifier tests
and the original 66 blocked-state fixture-provenance tests continue to exercise
the legacy fail-closed paths after the live repository gate became authorized
v2.

Do not edit these files to authorize distribution. The live authorized state is
covered by `support/tests/test_distribution_inventory_authorized.py` and
`support/tests/test_fixture_provenance.py`. The production distribution verifier
keeps the original blocked-v1 checks and dispatches authorized v2 to
`support/release/gate.py`; the fixture verifier retains its blocked-v1 checks.
