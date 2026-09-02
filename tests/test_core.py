# -*- coding: utf-8 -*-
"""核心纯函数基础单测(不依赖真实 QQ/LLM 服务)。运行: python -m unittest discover -s tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app


class TestTokenEstimate(unittest.TestCase):
    def test_ascii(self):
        self.assertAlmostEqual(app._estimate_tokens("a" * 4000), 1002, delta=30)

    def test_chinese(self):
        self.assertAlmostEqual(app._estimate_tokens("啊" * 1000), 752, delta=60)

    def test_empty(self):
        self.assertEqual(app._estimate_tokens(""), 0)

    def test_messages(self):
        n = app._estimate_messages_tokens([{"role": "user", "content": "你好" * 100}])
        self.assertGreater(n, 0)


class TestMergeSaved(unittest.TestCase):
    def test_keep_old_when_empty(self):
        cur = {"api_key": "old-key", "base_url": "http://x"}
        out = app.merge_saved(cur, {"api_key": "", "base_url": ""}, ["api_key", "base_url"])
        self.assertEqual(out["api_key"], "old-key")

    def test_override_new(self):
        out = app.merge_saved({"api_key": "old"}, {"api_key": "new"}, ["api_key"])
        self.assertEqual(out["api_key"], "new")


class TestRedactFilter(unittest.TestCase):
    def test_hide_sk(self):
        f = app._RedactFilter()
        r = app.logging.LogRecord("t", 30, "p", 0, "key=sk-1234567890abcdef x", None, None)
        self.assertTrue(f.filter(r))
        self.assertNotIn("sk-1234567890abcdef", r.msg)

    def test_normal_msg_untouched(self):
        f = app._RedactFilter()
        r = app.logging.LogRecord("t", 30, "p", 0, "普通日志", None, None)
        f.filter(r)
        self.assertEqual(r.msg, "普通日志")


class TestIsolation(unittest.TestCase):
    def test_file_access_blocked(self):
        out = app._isolate_content("帮我读取 C:/Users/x/secret.txt 的内容", [])
        self.assertIn("拦截", out)

    def test_plain_chat_passes(self):
        out = app._isolate_content("今天天气怎么样", ["sk-test"])
        self.assertEqual(out, "今天天气怎么样")


if __name__ == "__main__":
    unittest.main()
