import unittest

from src.cli import build_parser


class CliTests(unittest.TestCase):
    def test_safe_commands_are_registered(self):
        parser = build_parser()

        args = parser.parse_args([
            "self-test"
        ])

        self.assertEqual(
            args.command,
            "self-test",
        )


if __name__ == "__main__":
    unittest.main()
