import unittest

import agent
from global_config import global_config

PROMPTS = {
    "patch2pattern": lambda: agent._project(agent.patch2pattern_template),
    "patch2pattern-general": lambda: agent._project(agent.patch2pattern_general_template),
    "patch2checker": lambda: agent._project(agent.patch2checker_template),
    "check_report": lambda: agent._project(
        (agent.prompt_template_dir / "check_report.md").read_text()
    ),
    "label_commit": lambda: agent._project(agent.label_commit_template),
}


class PromptProjectTest(unittest.TestCase):
    def setUp(self):
        self.saved = dict(global_config._config)

    def tearDown(self):
        global_config._config = self.saved

    def render_all(self, config):
        global_config._config = config
        return {name: build() for name, build in PROMPTS.items()}

    def test_generic_project_has_no_kernel_framing(self):
        prompts = self.render_all(
            {"target_type": "compiledb", "target_options": {"name": "curl"}}
        )
        for name, text in prompts.items():
            self.assertNotIn("{{project", text, name)
            # Only the (labelled) kernel few-shot examples may mention the kernel.
            instructions = text.split("# Examples")[0]
            self.assertNotIn("Linux kernel", instructions, name)
            self.assertIn("curl, a C project", instructions, name)
        self.assertNotIn("DT/ACPI", prompts["check_report"])
        self.assertIn("allocation failure", prompts["check_report"])

    def test_linux_keeps_kernel_wording(self):
        prompts = self.render_all({"target_type": "linux"})
        self.assertIn("a patch to the Linux kernel", prompts["patch2pattern"])
        self.assertIn("real bug in the Linux kernel", prompts["check_report"])
        self.assertIn("DT/ACPI", prompts["check_report"])

    def test_explicit_project_description(self):
        prompts = self.render_all(
            {"target_type": "compiledb", "project": {"description": "SQLite, an embedded SQL database library written in C"}}
        )
        self.assertIn("a patch to SQLite, an embedded SQL database", prompts["patch2pattern"])

    def test_examples_are_labelled_with_source_project(self):
        prompts = self.render_all({"target_type": "compiledb", "target_options": {"name": "curl"}})
        self.assertIn("(from the Linux kernel; its functions and APIs are specific", prompts["patch2pattern"])


if __name__ == "__main__":
    unittest.main()
