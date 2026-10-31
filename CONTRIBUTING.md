# Contributing / 参与改进

Please keep disk deletion behind explicit allowlists, a read-only scan snapshot,
and a separate interactive confirmation. Do not introduce arbitrary shell
execution, an internet-facing HTTP listener, automatic upload, disabling of
Defender/SmartScreen, or silent elevation.

Run the tests before submitting changes:

```shell
python -m unittest discover -s tests
python -m unittest discover -s tests_v3
python -m unittest discover -s tests_v31
python -m unittest discover -s tests_v32
python -m unittest discover -s tests_v33
```

Use `python scripts/build_release.py --outdir dist` to create a source-only
release. The builder regenerates the manifest and rejects unsupported assets.
Report vulnerabilities using private vulnerability reporting when enabled.
Do not attach ZIPs containing personal reports, credentials or cached AI models.
