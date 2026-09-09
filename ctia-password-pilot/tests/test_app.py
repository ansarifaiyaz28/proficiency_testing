import importlib
import os
import tempfile
import unittest


class PasswordPilotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        os.environ["CTIA_DATA_DIR"] = cls.tempdir.name
        os.environ["CTIA_COOKIE_SECURE"] = "false"
        cls.module = importlib.import_module("app")
        cls.app = cls.module.app
        cls.app.config.update(TESTING=True)

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def setUp(self):
        with self.app.app_context():
            self.module.reset_device(self.module.get_db())
        self.client = self.app.test_client()

    def login(self, password="admin"):
        return self.client.post("/login", data={"username": "admin", "password": password})

    def csrf(self):
        cookie = self.client.get_cookie(self.module.COOKIE_NAME)
        with self.app.app_context():
            db = self.module.connect_database()
            row = db.execute(
                "SELECT csrf_token FROM sessions WHERE token_hash = ?",
                (self.module.token_digest(cookie.value),),
            ).fetchone()
            db.close()
            return row["csrf_token"]

    def enroll(self, password="Safe9!word"):
        self.login()
        return self.client.post(
            "/change-password",
            data={
                "csrf_token": self.csrf(),
                "current_password": "admin",
                "new_password": password,
                "confirm_password": password,
            },
        )

    def test_default_forces_change_before_normal_operation(self):
        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/change-password"))
        response = self.client.get("/")
        self.assertTrue(response.headers["Location"].endswith("/change-password"))

    def test_test_plan_page_is_not_exposed(self):
        self.assertEqual(self.client.get("/test-plan").status_code, 404)

    def test_password_policy(self):
        self.login()
        token = self.csrf()
        cases = ["short", "admin", "Goodaaa9!", "Good123x!"]
        for candidate in cases:
            response = self.client.post(
                "/change-password",
                data={
                    "csrf_token": token,
                    "current_password": "admin",
                    "new_password": candidate,
                    "confirm_password": candidate,
                },
            )
            self.assertEqual(response.status_code, 400, candidate)

    def test_fresh_password_enters_normal_operation_and_default_is_rejected(self):
        response = self.enroll()
        self.assertEqual(response.status_code, 302)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.assertEqual(self.login().status_code, 401)
        self.assertEqual(self.login("Safe9!word").status_code, 302)

    def test_wrong_password_and_rate_limit(self):
        for _ in range(5):
            self.assertEqual(self.login("Wrong9!pass").status_code, 401)
        response = self.login("Wrong9!pass")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "60")

    def test_operator_cannot_access_privileged_device_page(self):
        self.enroll()
        with self.app.app_context():
            db = self.module.connect_database()
            now = self.module.utc_now()
            db.execute(
                """INSERT INTO users
                   (username, password_hash, role, must_change_password, enabled, created_at, updated_at)
                   VALUES ('operator', ?, 'operator', 0, 1, ?, ?)""",
                (self.module.generate_password_hash("Role9!safe"), now, now),
            )
            db.commit()
            db.close()
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        response = self.client.post("/login", data={"username": "operator", "password": "Role9!safe"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/device").status_code, 403)

    def test_factory_reset_restores_mandatory_change(self):
        self.enroll()
        response = self.client.post("/factory-reset", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.login().status_code, 302)
        self.assertTrue(self.client.get("/").headers["Location"].endswith("/change-password"))

    def test_command_line_factory_reset_requires_no_login(self):
        self.enroll()
        self.assertEqual(self.module.command_line(["--factory-reset"]), 0)
        with self.app.app_context():
            db = self.module.connect_database()
            users = db.execute(
                "SELECT username, must_change_password FROM users ORDER BY id"
            ).fetchall()
            state = db.execute(
                "SELECT normal_operation, device_name FROM device_state WHERE singleton = 1"
            ).fetchone()
            sessions = db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            db.close()
        self.assertEqual([(row["username"], row["must_change_password"]) for row in users], [("admin", 1)])
        self.assertEqual(state["normal_operation"], 0)
        self.assertEqual(state["device_name"], "CTIA Password Pilot")
        self.assertEqual(sessions, 0)
        self.assertEqual(self.login().status_code, 302)


if __name__ == "__main__":
    unittest.main()
