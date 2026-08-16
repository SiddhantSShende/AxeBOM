# pypi-normalization

WARNING: THE NAME-NORMALIZATION FIXTURE.

PEP 503 says a PyPI project name is normalized by lowercasing and collapsing
runs of "-", "_" and "." into a single "-". So all of these are ONE project
each, however they were written:

    Django_REST_framework  ->  django-rest-framework
    PyYAML                 ->  pyyaml
    zope.interface         ->  zope-interface
    python-dateutil        ->  python-dateutil

**What it proves:** that the normalizer applies PEP 503 rather than comparing
raw strings. An implementation that does not will report PyYAML and pyyaml as
two components — the single most common dedup bug in Python SBOM tooling, and
one that inflates a component count without ever looking wrong.

zope.interface is the sharp case: the dot is a separator under PEP 503, not part
of the name, so zope.interface and zope-interface are the same project.
