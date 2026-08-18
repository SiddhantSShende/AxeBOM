"""HBOM — hardware bills of materials.

⚠ THIS IS IMPORT PLUS A DATA MODEL. IT IS NOT A SCANNER, AND NOTHING HERE
DISCOVERS ANYTHING.

There is no open-source tool that inspects a physical device and enumerates its
parts. An "HBOM scan" button that only reads a CSV is a lie the customer
discovers at exactly the wrong moment — usually while assembling evidence for an
audit, having assumed for months that something was watching their hardware.

So every label in this package, in the API and in the UI says *import*. See
`docs/04-OSINT-INTEGRATION.md` and the honest-labels section of `CLAUDE.md`.

⚠ NO GPL. `django-bom` is GPL-3.0 and is a Django *application* rather than a
library, so importing it would both make this worker a derivative work and not
work. It is a SCHEMA REFERENCE ONLY: never installed, never imported. The model
below is ours.
"""
