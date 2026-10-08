import unittest

from webtech_inspector.models import ContentEndpoint, MetaDataEndpoint
from webtech_inspector.models import RegexSignature, PackageSignature, Signature, signature_from_dict


def make_html(content):
    return ContentEndpoint("E1", content, "homepage", "/", 200, "HTML")


def make_package(content):
    return ContentEndpoint("E2", content, "package.json", "/package.json", 200, "JSON")


JQUERY = RegexSignature("S1", "jQuery", "JavaScript Library",
                        r"jquery[-.]?[0-9]", r"jquery[-.]([0-9]+\.[0-9]+\.[0-9]+)")
REACT = PackageSignature("S2", "React", "JavaScript Framework", "react")


class TestRegexSignature(unittest.TestCase):
    def test_match_and_version(self):
        page = make_html("<script src='jquery-3.4.1.min.js'></script>")
        self.assertTrue(JQUERY.match(page))
        self.assertEqual(JQUERY.extract_version(page), "3.4.1")

    def test_no_match(self):
        page = make_html("<p>hello</p>")
        self.assertFalse(JQUERY.match(page))
        self.assertIsNone(JQUERY.extract_version(page))

    def test_no_version_pattern(self):
        express = RegexSignature("S3", "Express", "Web Server", r"x-powered-by:\s*express")
        headers = MetaDataEndpoint("E3", "X-Powered-By: Express", "headers", "headers")
        self.assertTrue(express.match(headers))
        self.assertIsNone(express.extract_version(headers))

    def test_bad_regex(self):
        with self.assertRaises(ValueError):
            RegexSignature("S9", "Broken", "Test", "jquery[")


class TestPackageSignature(unittest.TestCase):
    def test_exact_version(self):
        package = make_package('{"dependencies": {"react": "17.0.2"}}')
        self.assertTrue(REACT.match(package))
        self.assertEqual(REACT.extract_version(package), "17.0.2")

    def test_dev_dependencies(self):
        package = make_package('{"devDependencies": {"react": "18.2.0"}}')
        self.assertEqual(REACT.extract_version(package), "18.2.0")

    def test_range_is_unknown_version(self):
        package = make_package('{"dependencies": {"react": "^17.0.2"}}')
        self.assertTrue(REACT.match(package))
        self.assertIsNone(REACT.extract_version(package))

    def test_html_is_skipped(self):
        self.assertFalse(REACT.match(make_html("react")))

    def test_broken_json(self):
        with self.assertRaises(ValueError):
            REACT.match(make_package('{"dependencies": '))

    def test_json_that_is_not_a_package_file(self):
        self.assertFalse(REACT.match(make_package("[1, 2]")))
        self.assertFalse(REACT.match(make_package('{"status": "ok"}')))
        self.assertFalse(REACT.match(make_package('{"dependencies": ["react"]}')))

    def test_version_that_is_not_text(self):
        package = make_package('{"dependencies": {"react": 17}}')
        self.assertTrue(REACT.match(package))
        self.assertIsNone(REACT.extract_version(package))


class TestSignatureBase(unittest.TestCase):
    def test_cannot_create_base(self):
        with self.assertRaises(TypeError):
            Signature("S1", "X", "Y")

    def test_from_dict(self):
        regex = signature_from_dict({"signature_id": "S1", "kind": "regex", "tech_name": "Vue",
                                     "category": "JavaScript Framework", "match_pattern": "vue"})
        package = signature_from_dict({"signature_id": "S2", "kind": "package", "tech_name": "React",
                                       "category": "JavaScript Framework", "package_name": "react"})
        self.assertIsInstance(regex, RegexSignature)
        self.assertIsInstance(package, PackageSignature)
        with self.assertRaises(ValueError):
            signature_from_dict({"signature_id": "S3", "kind": "magic", "tech_name": "X", "category": "Y"})


if __name__ == "__main__":
    unittest.main()
