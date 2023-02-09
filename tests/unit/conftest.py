import sys

import charms.unit_test

sys.path.append("reactive")
charms.unit_test.patch_reactive()
charms.unit_test.patch_module("charms.leadership")
