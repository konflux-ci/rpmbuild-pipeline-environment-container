#!/usr/bin/python3
"""Test that image versions are the same."""

import unittest


class TestCheckTestImage(unittest.TestCase):
    """Test that image versions are the same."""
    def test_check_test_image(self):
        """Test that container image is the same version as image in containerfile."""
        is_same = False
        with (open('.github/workflows/gh-action-testsuite.yaml', 'r', encoding='utf-8') as gh_action,
              open('Containerfile', 'r', encoding='utf-8') as containerfile):
            for line_gh in gh_action:
                if 'image: ' in line_gh:
                    image_gh = line_gh.split('image: ')[1].strip()
                    for line_c in containerfile:
                        if 'FROM ' in line_c:
                            image_c = line_c.split('FROM ')[1].strip()
                            if image_c == image_gh:
                                is_same = True
                                break
        self.assertTrue(is_same)
