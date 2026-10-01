import tempfile
import unittest
from pathlib import Path

import yaml

from global_config import TARGET_BUILDERS, GlobalConfig


class TargetRegistryTest(unittest.TestCase):
    def test_unknown_target_type_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "c.yaml"
            keys = Path(tmp) / "k.yaml"
            keys.write_text("providers: {}\n")
            cfg.write_text(yaml.safe_dump({"target_type": "cmake-but-misspelled",
                                           "result_dir": str(Path(tmp) / "r"),
                                           "key_file": str(keys), "LLVM_dir": tmp}))
            config = object.__new__(GlobalConfig)
            config._config, config._keys, config._initialized = {}, {}, False
            with self.assertRaisesRegex(ValueError, "Unknown target_type 'cmake-but-misspelled'"):
                config.setup(str(cfg))

    def test_registry_has_generic_target(self):
        self.assertEqual({"linux", "v8", "compiledb"}, set(TARGET_BUILDERS))


if __name__ == "__main__":
    unittest.main()
