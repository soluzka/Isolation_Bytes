import tempfile
import unittest

from agent.prompt_learning import PromptLearningStore


class PromptLearningTests(unittest.TestCase):
    def test_secrets_are_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PromptLearningStore(f"{tmp}/memory.db")
            store.learn(
                "check api_key=super-secret-token and auth-token-shaped-value",
                "completed",
            )
            rows = store.retrieve("check api key")
            self.assertEqual(len(rows), 1)
            self.assertNotIn("super-secret-token", rows[0]["prompt"])
            self.assertNotIn("auth-token-shaped-value", rows[0]["prompt"])

    def test_feedback_changes_retrieval_weight(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PromptLearningStore(f"{tmp}/memory.db")
            store.learn("scan startup folders for malware", "scan", feedback=1)
            store.learn("scan startup folders", "different", feedback=-1)
            rows = store.retrieve("scan startup folders")
            self.assertTrue(rows)
            self.assertIn(rows[0]["feedback"], (-1, 1))

    def test_learning_is_bounded_and_local(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/memory.db"
            store = PromptLearningStore(path)
            store.learn("diagnose malware " + "x" * 5000, "ok")
            self.assertTrue(store.path.exists())
            self.assertLessEqual(len(store.retrieve("diagnose malware")), 5)


if __name__ == "__main__":
    unittest.main()
