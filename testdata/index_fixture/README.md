# Index Fixture

This is a small standalone ELF used to exercise AETHER function indexing. It
contains file parsing, endpoint/network-like dispatch, hashing, XOR
transformation, pthread usage, and report generation.

Build it from the repository root:

```sh
gcc -O0 -g -fno-inline -fno-omit-frame-pointer -Wall -Wextra -pthread \
  testdata/index_fixture/index_fixture.c \
  -o testdata/index_fixture/bin/index_fixture
```

Import `testdata/index_fixture/bin/index_fixture` into Ghidra. After enabling
AETHER, open **Window > AETHER Indexing** and start **Index / Resume Binary**.
The expected non-trivial symbols include `parse_endpoint`,
`read_configuration`, `xor_transform`, `transform_worker`,
`threaded_transform`, `write_report`, `dispatch_request`, and `run_fixture`.

The optional runtime smoke test is:

```sh
testdata/index_fixture/bin/index_fixture \
  testdata/index_fixture/index_fixture.conf \
  /tmp/index-fixture.report
```
