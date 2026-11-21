# Architecture
`cli.py` (Typer) invokes `core.engine.analyze`; pipeline parses/refangs/normalizes IOC, checks cache, queries eligible providers, calculates weighted score/verdict and confidence, classifies from provider evidence, then persists history.

Packages: `ioc` validation; `providers` integrations; `core` orchestration/cache/database/HTTP; `analysis` scoring/classification/change detection; `reporting` output serialization; `utils` terminal banner. Provider failures are isolated. Cache/history are local SQLite under XDG data.
