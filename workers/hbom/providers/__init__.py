"""Part-data enrichment providers.

⚠ `manual` IS THE DEFAULT, AND IT IS THE PATH THAT MUST WORK.

Nexar (Altium, formerly Octopart) and Mouser are commercial, quota-limited and
require an API key. Making either a hard dependency would mean HBOM does not
work for a customer who has not signed up to a third-party parts database — for
a feature whose entire purpose is recording hardware they already own.

So `manual` returns nothing, is selected when nothing is configured, and is the
provider the tests exercise. An unconfigured commercial provider is SKIPPED
cleanly: no error, and no call with an empty credential.
"""

from .base import Enrichment, PartDataProvider, resolve
from .manual import ManualProvider

__all__ = ["Enrichment", "ManualProvider", "PartDataProvider", "resolve"]
