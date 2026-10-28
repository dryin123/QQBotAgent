# -*- coding: utf-8 -*-
"""核心纯函数基础单测(不依赖真实 QQ/LLM 服务)。运行: python -m unittest discover -s tests"""
import os
import sys
import asyncio
import tempfile
import time
import unittest

import aiohttp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import main as app


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

    def test_hide_secret_in_args(self):
        """真值走 record.args 时也必须打码，只扫 record.msg 会漏。"""
        f = app._RedactFilter()
        r = app.logging.LogRecord("t", 30, "p", 0, "api_key=%s", ("sk-abcdef1234567890",), None)
        f.filter(r)
        self.assertNotIn("sk-abcdef1234567890", r.getMessage())
        self.assertIn("***", r.getMessage())

    def test_hide_bearer_in_args(self):
        f = app._RedactFilter()
        r = app.logging.LogRecord("t", 30, "p", 0, "auth %s", ("Bearer abcdefghijklmnop",), None)
        f.filter(r)
        self.assertNotIn("abcdefghijklmnop", r.getMessage())


class TestCompression(unittest.TestCase):
    """压缩阈值收敛与失败退避。"""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="qqbot_test_")
        os.makedirs(self.base, exist_ok=True)
        self.mgr = app.SessionManager(
            store_file=os.path.join(self.base, "sessions.json"),
            history_temp_dir=os.path.join(self.base, "temp"),
        )

    def tearDown(self):
        import shutil
        self.mgr._compress_backoff.clear()
        self.mgr.close()
        shutil.rmtree(self.base, ignore_errors=True)

    def test_limit_capped_by_small_window(self):
        """8k 窗口：阈值必须收敛到窗口 60% 以内，否则请求本身超窗。"""
        self.mgr.compression_token_limit = 60000
        self.mgr.model_context_tokens = 8192
        self.assertEqual(self.mgr._effective_token_limit(), int(8192 * 0.6))

    def test_limit_kept_when_window_large(self):
        self.mgr.compression_token_limit = 20000
        self.mgr.model_context_tokens = 128000
        self.assertEqual(self.mgr._effective_token_limit(), 20000)

    def test_limit_ignored_when_window_unknown(self):
        self.mgr.compression_token_limit = 60000
        self.mgr.model_context_tokens = 0
        self.assertEqual(self.mgr._effective_token_limit(), 60000)

    def test_backoff_grows_and_caps(self):
        key = "u1:1"
        self.mgr._note_compress_failure(key)
        first = self.mgr._compress_backoff[key]["next"] - time.time()
        self.assertAlmostEqual(first, 60, delta=5)

        for _ in range(10):
            self.mgr._note_compress_failure(key)
        st = self.mgr._compress_backoff[key]
        self.assertEqual(st["count"], 11)
        remaining = st["next"] - time.time()
        self.assertLessEqual(remaining, 1800)
        self.assertGreater(remaining, 1700)

    def test_backoff_blocks_until_deadline(self):
        key = "u1:2"
        self.mgr._note_compress_failure(key)
        st = self.mgr._compress_backoff[key]
        self.assertGreater(st["next"], time.time())


class TestPathGuard(unittest.TestCase):
    """外部标识符拼路径时不得越出允许根。"""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="qqbot_test_")
        os.makedirs(self.base, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def _inside(self, path):
        root = os.path.realpath(self.base)
        return os.path.commonpath([root, os.path.realpath(path)]) == root

    def test_group_id_traversal(self):
        for evil in ("1/../../escaped", "../escaped", "..\\escaped", "1/../../../x"):
            d = app._temp_dir_for_group("u1", evil, self.base)
            self.assertTrue(self._inside(d), f"{evil!r} 越界 -> {d}")

    def test_user_id_traversal(self):
        for evil in ("../../escaped", "..\\..\\escaped", "a/../../b", ".."):
            d = app._temp_dir_for_group(evil, 1, self.base)
            self.assertTrue(self._inside(d), f"{evil!r} 越界 -> {d}")

    def test_group_id_coerced(self):
        self.assertEqual(app._safe_group_id("12"), 12)
        self.assertEqual(app._safe_group_id(7), 7)
        self.assertEqual(app._safe_group_id("1/../x"), 0)
        self.assertEqual(app._safe_group_id(None), 0)

    def test_normal_input_kept(self):
        d = app._temp_dir_for_group("ABCDEF123", 3, self.base)
        self.assertTrue(d.endswith("ABCDEF123_g3"), d)


class TestMemory(unittest.TestCase):
    """结构化记忆：解析容错、合并去重、渲染紧凑。"""

    def test_parse_fenced_json(self):
        d = app._parse_memory_json('```json\n{"facts":[{"k":"工作","v":"便利店"}]}\n```')
        self.assertIsNotNone(d)
        self.assertEqual(d["facts"][0]["k"], "工作")

    def test_parse_with_prose_around(self):
        d = app._parse_memory_json('好的，结果如下：\n{"facts":[{"k":"a","v":"b"}]}\n以上。')
        self.assertIsNotNone(d)

    def test_parse_trailing_comma(self):
        d = app._parse_memory_json('{"facts":[{"k":"a","v":"b"},],}')
        self.assertIsNotNone(d)

    def test_parse_garbage(self):
        self.assertIsNone(app._parse_memory_json("这不是 JSON"))
        self.assertIsNone(app._parse_memory_json(""))
        self.assertIsNone(app._parse_memory_json("[1,2,3]"))

    def test_merge_overrides_old_value(self):
        prev = {"facts": [{"k": "工作", "v": "学生"}], "events": ["旧事件"]}
        raw = {"facts": [{"k": "工作", "v": "便利店夜班"}, {"k": "宠物", "v": "两只猫"}],
               "events": ["新事件"]}
        m = app._normalize_memory(raw, prev)
        facts = {f["k"]: f["v"] for f in m["facts"]}
        self.assertEqual(facts["工作"], "便利店夜班")
        self.assertEqual(facts["宠物"], "两只猫")
        self.assertIn("旧事件", m["events"])
        self.assertIn("新事件", m["events"])

    def test_events_capped_and_ordered(self):
        raw = {"events": [f"e{i}" for i in range(100)]}
        m = app._normalize_memory(raw)
        self.assertEqual(len(m["events"]), app._MEM_MAX_EVENTS)
        self.assertEqual(m["events"][-1], "e99")

    def test_bad_types_are_coerced(self):
        raw = {"user": {"nick": 123, "traits": "喜欢猫"},
               "facts": "不是列表",
               "tasks": [{"task": "写周报", "status": "已完成"}]}
        m = app._normalize_memory(raw)
        self.assertEqual(m["user"]["nick"], "123")
        self.assertEqual(m["user"]["traits"], ["喜欢猫"])
        self.assertEqual(m["tasks"][0]["status"], "done")
        self.assertEqual(m["facts"], [])

    def test_render_compact_and_skips_done(self):
        m = app._normalize_memory({
            "user": {"nick": "小明"},
            "facts": [{"k": "工作", "v": "夜班"}],
            "tasks": [{"task": "写周报", "status": "open"}, {"task": "已交差", "status": "done"}],
        })
        txt = app._render_memory(m)
        self.assertIn("称呼：小明", txt)
        self.assertIn("工作=夜班", txt)
        self.assertIn("写周报", txt)
        self.assertNotIn("已交差", txt)

    def test_render_smaller_than_raw_json(self):
        raw = {"facts": [{"k": f"k{i}", "v": f"v{i}"} for i in range(10)]}
        m = app._normalize_memory(raw)
        import json as _json
        self.assertLess(len(app._render_memory(m)), len(_json.dumps(m, ensure_ascii=False)))

    def test_memory_roundtrip(self):
        base = tempfile.mkdtemp(prefix="qqbot_test_")
        os.makedirs(base, exist_ok=True)
        try:
            mem = app._normalize_memory({"facts": [{"k": "a", "v": "b"}]})
            app._save_memory("u1", 1, mem, base)
            got = app._load_memory("u1", 1, base)
            self.assertIsNotNone(got)
            self.assertEqual(got["facts"][0]["k"], "a")
            self.assertIsNone(app._load_memory("nobody", 9, base))
        finally:
            import shutil
            shutil.rmtree(base, ignore_errors=True)


class _FakeProvider:
    """按固定 JSON 回包，用于跑通压缩链路。"""

    def __init__(self, reply):
        self.reply = reply

    async def chat_completion(self, *args, **kwargs):
        return self.reply

    async def chat_completion_resilient(self, *args, **kwargs):
        return self.reply


class TestCompressionFlow(unittest.IsolatedAsyncioTestCase):
    """端到端：对话 -> 触发压缩 -> 落 memory.json -> 上下文注入。"""

    async def asyncSetUp(self):
        self.base = tempfile.mkdtemp(prefix="qqbot_test_")
        os.makedirs(self.base, exist_ok=True)
        self.mgr = app.SessionManager(
            max_rounds=20,
            store_file=os.path.join(self.base, "sessions.json"),
            history_temp_dir=os.path.join(self.base, "temp"),
        )
        self.mgr.compression_enabled = True
        self.mgr.compression_token_limit = 100
        self.mgr.model_context_tokens = 0

    async def asyncTearDown(self):
        import shutil
        self.mgr.close()
        shutil.rmtree(self.base, ignore_errors=True)

    async def test_compress_writes_memory_and_shrinks_history(self):
        for i in range(6):
            await self.mgr.get_context("u1", "问题" * 40)
            await self.mgr.add_response("u1", "问题" * 40, "回答" * 40)

        before = len(self.mgr.sessions["u1"]["groups"][0]["history"])
        reply = '{"user":{"nick":"小明"},"facts":[{"k":"工作","v":"夜班"}],"events":["聊到排班"]}'
        started = await self.mgr.maybe_compress("u1", _FakeProvider(reply))
        self.assertTrue(started)
        for _ in range(30):
            await asyncio.sleep(0.02)
            if not self.mgr._compressing_users:
                break

        after = len(self.mgr.sessions["u1"]["groups"][0]["history"])
        self.assertLess(after, before)
        self.assertEqual(after, 4)  # 保留最近 2 轮

        mem = app._load_memory("u1", 1, self.mgr.history_temp_dir)
        self.assertIsNotNone(mem)
        self.assertEqual(mem["user"]["nick"], "小明")
        self.assertEqual(mem["facts"][0]["k"], "工作")

        ctx = await self.mgr.get_context("u1", "还在吗")
        joined = "\n".join(m["content"] for m in ctx if m["role"] == "system")
        self.assertIn("小明", joined)
        self.assertIn("工作=夜班", joined)
        # 被摘要覆盖掉的原文应进归档，不是直接丢弃
        self.assertGreater(self.mgr.store.archive_count("u1"), 0)

    async def test_non_json_reply_degrades_to_text(self):
        for _ in range(6):
            await self.mgr.get_context("u2", "问题" * 40)
            await self.mgr.add_response("u2", "问题" * 40, "回答" * 40)

        started = await self.mgr.maybe_compress("u2", _FakeProvider("这是一段没有 JSON 的普通摘要文本。"))
        self.assertTrue(started)
        for _ in range(30):
            await asyncio.sleep(0.02)
            if not self.mgr._compressing_users:
                break

        # 降级内容进 memory.json 的 note 字段，不再单独写 summary.txt
        mem = app._load_memory("u2", 1, self.mgr.history_temp_dir)
        self.assertIsNotNone(mem)
        self.assertIn("普通摘要文本", mem.get("note", ""))
        ctx = await self.mgr.get_context("u2", "继续")
        joined = "\n".join(m["content"] for m in ctx if m["role"] == "system")
        self.assertIn("普通摘要文本", joined)

    async def test_failure_sets_backoff(self):
        for _ in range(6):
            await self.mgr.get_context("u3", "问题" * 40)
            await self.mgr.add_response("u3", "问题" * 40, "回答" * 40)

        started = await self.mgr.maybe_compress("u3", _FakeProvider(""))
        self.assertTrue(started)
        for _ in range(30):
            await asyncio.sleep(0.02)
            if not self.mgr._compressing_users:
                break

        self.assertIn("u3:1", self.mgr._compress_backoff)
        again = await self.mgr.maybe_compress("u3", _FakeProvider("{}"))
        self.assertFalse(again)  # 退避期内不再触发


class TestSessionStore(unittest.TestCase):
    """SQLite 持久化：单行更新、旧 JSON 迁移、删除。"""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="qqbot_test_")
        os.makedirs(self.base, exist_ok=True)
        self.store_file = os.path.join(self.base, "sessions.json")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def _new_mgr(self):
        return app.SessionManager(store_file=self.store_file,
                                  history_temp_dir=os.path.join(self.base, "temp"))

    @staticmethod
    def _sess(rounds=1):
        return {"groups": [{"history": [{"role": "user", "content": "hi"}],
                            "rounds": rounds, "compressed": []}],
                "current_group": 0, "last_used": time.time()}

    def test_single_user_persist_and_reload(self):
        sm = self._new_mgr()
        sm.sessions["u1"] = self._sess()
        sm._save("u1")
        sm.close()

        sm2 = self._new_mgr()
        self.assertIn("u1", sm2.sessions)
        self.assertEqual(sm2.sessions["u1"]["groups"][0]["rounds"], 1)
        sm2.close()

    def test_delete_removes_row(self):
        sm = self._new_mgr()
        sm.sessions["u1"] = self._sess()
        sm._save("u1")
        sm.store.delete("u1")
        self.assertNotIn("u1", sm.store.load_all())
        sm.close()

    def test_legacy_json_migrated(self):
        import json as _json
        with open(self.store_file, "w", encoding="utf-8") as f:
            _json.dump({"u9": self._sess(3)}, f, ensure_ascii=False)

        sm = self._new_mgr()
        self.assertIn("u9", sm.sessions)
        self.assertEqual(sm.sessions["u9"]["groups"][0]["rounds"], 3)
        self.assertTrue(os.path.exists(self.store_file + ".migrated"))
        # 再开一次读的是库，不重复迁移
        sm.close()
        sm2 = self._new_mgr()
        self.assertIn("u9", sm2.sessions)
        sm2.close()

    def test_db_file_created_next_to_json(self):
        sm = self._new_mgr()
        self.assertTrue(os.path.exists(self.store_file.replace(".json", ".db")))
        sm.close()


class TestRetryPolicy(unittest.TestCase):
    def test_client_errors_not_retried(self):
        self.assertFalse(app._is_retryable_error(Exception("OpenAI API error: 401 - bad key")))
        self.assertFalse(app._is_retryable_error(Exception("OpenAI API error: 400 - bad request")))
        self.assertFalse(app._is_retryable_error(Exception("OpenAI API error: 403 - forbidden")))

    def test_server_and_rate_limit_retried(self):
        self.assertTrue(app._is_retryable_error(Exception("OpenAI API error: 429 - slow down")))
        self.assertTrue(app._is_retryable_error(Exception("OpenAI API error: 500 - boom")))
        self.assertTrue(app._is_retryable_error(Exception("OpenAI API error: 503 - unavailable")))

    def test_network_errors_retried(self):
        self.assertTrue(app._is_retryable_error(asyncio.TimeoutError()))
        self.assertTrue(app._is_retryable_error(aiohttp.ClientError("connection reset")))

    def test_unknown_error_not_retried(self):
        self.assertFalse(app._is_retryable_error(ValueError("bad json")))


class TestBotGuards(unittest.TestCase):
    """去重表与按用户锁。"""

    def setUp(self):
        class _P:
            def _register_secret(self, s):
                pass

        self.base = tempfile.mkdtemp(prefix="qqbot_test_")
        os.makedirs(self.base, exist_ok=True)
        sm = app.SessionManager(store_file=os.path.join(self.base, "s.json"),
                                history_temp_dir=os.path.join(self.base, "t"))
        self.bot = app.QQBot("app", "sec", _P(), sm, {}, self.base)
        self.sm = sm

    def tearDown(self):
        import shutil
        self.sm.close()
        shutil.rmtree(self.base, ignore_errors=True)

    def test_same_user_same_lock(self):
        a = self.bot._user_lock("openid-1")
        b = self.bot._user_lock("openid-1")
        c = self.bot._user_lock("openid-2")
        self.assertIs(a, b)
        self.assertIsNot(a, c)

    def test_seen_ids_bounded(self):
        self.assertEqual(self.bot._seen_msg_max, 500)
        for i in range(600):
            self.bot._seen_msg_ids[f"m{i}"] = time.time()
            while len(self.bot._seen_msg_ids) > self.bot._seen_msg_max:
                self.bot._seen_msg_ids.popitem(last=False)
        self.assertEqual(len(self.bot._seen_msg_ids), 500)
        self.assertNotIn("m0", self.bot._seen_msg_ids)


class TestArchive(unittest.TestCase):
    """归档：写入、检索、裁剪、清除、翻篇归档。"""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="qqbot_test_")
        self.sm = app.SessionManager(store_file=os.path.join(self.base, "s.json"),
                                     history_temp_dir=os.path.join(self.base, "t"))

    def tearDown(self):
        import shutil
        self.sm.close()
        shutil.rmtree(self.base, ignore_errors=True)

    def _seed(self, uid="u1"):
        now = time.time()
        self.sm.store.archive_add(uid, 1, [
            {"role": "user", "content": "我在便利店上夜班，养了两只猫", "ts": now - 86400},
            {"role": "assistant", "content": "记住了，夜班注意休息", "ts": now - 86000},
        ])

    def test_write_and_count(self):
        self._seed()
        self.assertEqual(self.sm.store.archive_count("u1"), 2)
        self.assertEqual(self.sm.store.archive_count(), 2)

    def test_long_query_hits_with_context(self):
        self._seed()
        hits = self.sm.store.archive_search("u1", "便利店")
        self.assertTrue(any("便利店" in h["content"] for h in hits))
        # 命中后带上下文，相邻那条也要回来
        self.assertEqual(len(hits), 2)

    def test_expand_false_returns_only_hits(self):
        self._seed()
        strict = self.sm.store.archive_search("u1", "便利店", expand=False)
        self.assertEqual(len(strict), 1)
        self.assertIn("便利店", strict[0]["content"])

    def test_short_query_falls_back_to_like(self):
        """trigram 对两字词无效，必须回落 LIKE。"""
        self._seed()
        hits = self.sm.store.archive_search("u1", "夜班")
        self.assertEqual(len(hits), 2)

    def test_miss_returns_empty(self):
        self._seed()
        self.assertEqual(self.sm.store.archive_search("u1", "火星"), [])
        self.assertEqual(self.sm.store.archive_search("u1", ""), [])

    def test_symbol_only_query_not_match_all(self):
        """纯符号查询清洗后是空串，拼成 LIKE '%%' 会把整张表捞出来。"""
        self._seed()
        self.assertEqual(self.sm.store.archive_search("u1", "%%%___###"), [])
        self.assertEqual(self.sm.store.archive_search("u1", "___"), [])
        self.assertEqual(app._query_terms("%%%___###"), [])

    def test_scoped_by_user(self):
        self._seed("u1")
        self.assertEqual(self.sm.store.archive_search("u2", "便利店"), [])

    def test_trim_keeps_newest(self):
        now = time.time()
        self.sm.store.archive_add("u1", 1, [
            {"role": "user", "content": f"第{i}条", "ts": now - (10 - i)} for i in range(10)
        ])
        removed = self.sm.store.archive_trim("u1", 3)
        self.assertEqual(removed, 7)
        self.assertEqual(self.sm.store.archive_count("u1"), 3)
        kept = [r["content"] for r in self.sm.store.archive_list("u1", 10)]
        self.assertIn("第9条", kept)
        self.assertNotIn("第0条", kept)

    def test_purge(self):
        self._seed()
        self.assertEqual(self.sm.store.archive_purge("u1"), 2)
        self.assertEqual(self.sm.store.archive_count("u1"), 0)

    def test_roll_group_archives_old_history(self):
        self.sm.sessions["u1"] = {
            "groups": [{"history": [{"role": "user", "content": "翻篇前的话"},
                                    {"role": "assistant", "content": "翻篇前的回复"}],
                        "rounds": 5, "compressed": []}],
            "current_group": 0, "last_used": time.time(),
        }
        self.sm._roll_group("u1", self.sm.sessions["u1"])
        self.assertEqual(self.sm.store.archive_count("u1"), 2)
        self.assertEqual(len(self.sm.sessions["u1"]["groups"]), 2)


class TestQueryTerms(unittest.TestCase):
    """切词：按虚词切块，不产生跨词碎片。"""

    def test_cuts_on_stopwords(self):
        terms = app._query_terms("你还记得我养的那只猫吗")
        self.assertIn("只猫", terms)
        self.assertNotIn("你还记", terms)
        self.assertNotIn("得我养", terms)

    def test_no_pure_stopword_term(self):
        for t in app._query_terms("你还记得我养的那只猫吗"):
            self.assertGreaterEqual(len(t), 2)
            self.assertLessEqual(len(t), 6)
            self.assertFalse(all(c in app._STOP_CHARS for c in t))

    def test_english_kept(self):
        self.assertIn("docker", app._query_terms("docker 镜像怎么构建"))

    def test_empty(self):
        self.assertEqual(app._query_terms(""), [])
        self.assertEqual(app._query_terms("的了呢吧"), [])


class TestPrivacy(unittest.TestCase):
    """删除后文件里不应残留明文。"""

    def test_purged_content_not_recoverable(self):
        d = tempfile.mkdtemp(prefix="qqbot_test_")
        p = os.path.join(d, "t.db")
        marker = "私密内容MARKER93841"
        store = app._SessionStore(p)
        store.archive_add("u1", 1, [{"role": "user", "content": marker * 20}])
        self.assertGreater(store.archive_count("u1"), 0)
        store.archive_purge("u1")
        store.close()
        blob = b""
        for fn in os.listdir(d):
            with open(os.path.join(d, fn), "rb") as f:
                blob += f.read()
        self.assertNotIn(marker.encode("utf-8"), blob)
        import shutil
        shutil.rmtree(d, ignore_errors=True)


class TestSchemaAndCaps(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="qqbot_test_")
        self.store = app._SessionStore(os.path.join(self.base, "s.db"))

    def tearDown(self):
        self.store.close()
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def test_schema_version_written(self):
        v = self.store._conn.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(int(v), app._SCHEMA_VERSION)

    def test_fts_available(self):
        self.assertTrue(self.store._fts)

    def test_total_cap_trims_oldest(self):
        now = time.time()
        self.store.archive_add("u1", 1, [
            {"role": "user", "content": f"记录{i}", "ts": now + i} for i in range(20)
        ])
        removed = self.store.archive_trim_total(5)
        self.assertEqual(removed, 15)
        self.assertEqual(self.store.archive_count(), 5)
        kept = [r["content"] for r in self.store.archive_list("u1", 10)]
        self.assertIn("记录19", kept)
        self.assertNotIn("记录0", kept)

    def test_total_cap_noop_when_under(self):
        self.store.archive_add("u1", 1, [{"role": "user", "content": "只有一条"}])
        self.assertEqual(self.store.archive_trim_total(100), 0)
        self.assertEqual(self.store.archive_count(), 1)


class TestMessagePersistence(unittest.TestCase):
    """消息增量持久化：重启恢复、不重复、截断重写、组号重排。"""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="qqbot_test_")
        self.store_file = os.path.join(self.base, "sessions.json")
        self.mgr = self._new()

    def tearDown(self):
        import shutil
        try:
            self.mgr.close()
        except Exception:
            pass
        shutil.rmtree(self.base, ignore_errors=True)

    def _new(self):
        return app.SessionManager(store_file=self.store_file,
                                  history_temp_dir=os.path.join(self.base, "temp"))

    def _hist(self, sm, uid="u1", n=2):
        g = sm.sessions[uid]["groups"][0]
        g["history"] = [{"role": "user" if i % 2 == 0 else "assistant",
                         "content": f"消息{i}"} for i in range(n)]
        g["rounds"] = n // 2
        return g

    def test_survives_reload(self):
        self.mgr._ensure_user("u1")
        self._hist(self.mgr, n=4)
        self.mgr._save("u1")
        self.mgr.close()

        self.mgr = self._new()
        hist = self.mgr.sessions["u1"]["groups"][0]["history"]
        self.assertEqual(len(hist), 4)
        self.assertEqual(hist[0]["content"], "消息0")
        self.assertEqual(hist[3]["content"], "消息3")

    def test_incremental_does_not_duplicate(self):
        self.mgr._ensure_user("u1")
        self._hist(self.mgr, n=2)
        self.mgr._save("u1")
        self._hist(self.mgr, n=4)
        self.mgr._save("u1")
        self.assertEqual(self.mgr.store.messages_count(), 4)

    def test_truncation_rewrites_group(self):
        self.mgr._ensure_user("u1")
        self._hist(self.mgr, n=6)
        self.mgr._save("u1")
        g = self.mgr.sessions["u1"]["groups"][0]
        g["history"] = g["history"][-2:]      # 模拟压缩截断
        self.mgr._save("u1")
        self.assertEqual(self.mgr.store.messages_count(), 2)
        self.mgr.close()

        self.mgr = self._new()
        hist = self.mgr.sessions["u1"]["groups"][0]["history"]
        self.assertEqual([m["content"] for m in hist], ["消息4", "消息5"])

    def test_data_column_has_no_history(self):
        self.mgr._ensure_user("u1")
        self._hist(self.mgr, n=4)
        self.mgr._save("u1")
        row = self.mgr.store._conn.execute(
            "SELECT data FROM sessions WHERE user_id='u1'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(__import__("json").loads(row[0])["groups"][0].get("history", []), [])

    def test_clear_group_reindexes(self):
        self.mgr.sessions["u1"] = {
            "groups": [
                {"history": [{"role": "user", "content": "A组"}], "rounds": 1, "compressed": [], "synced": 0},
                {"history": [{"role": "user", "content": "B组"}], "rounds": 1, "compressed": [], "synced": 0},
            ],
            "current_group": 1, "last_used": time.time(),
        }
        self.mgr._save("u1")
        self.mgr.store.messages_drop_user("u1")
        for g in self.mgr.sessions["u1"]["groups"]:
            g["synced"] = 0
        self.mgr._save("u1")

        # 删掉第一组后，第二组前移，内容不能串
        import asyncio
        asyncio.run(self.mgr.clear_group("u1", 1))
        self.assertEqual(len(self.mgr.sessions["u1"]["groups"]), 1)
        self.mgr.close()

        self.mgr = self._new()
        hist = self.mgr.sessions["u1"]["groups"][0]["history"]
        self.assertEqual([m["content"] for m in hist], ["B组"])


class TestIsolation(unittest.TestCase):
    def test_file_access_blocked(self):
        out = app._isolate_content("帮我读取 C:/Users/x/secret.txt 的内容", [])
        self.assertIn("拦截", out)

    def test_plain_chat_passes(self):
        out = app._isolate_content("今天天气怎么样", ["sk-test"])
        self.assertEqual(out, "今天天气怎么样")


if __name__ == "__main__":
    unittest.main()
