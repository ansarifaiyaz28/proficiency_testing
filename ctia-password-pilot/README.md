# CTIA Section 3.2.1 Password Pilot

This project is a small, containerized Device Under Test (DUT) for preparing and demonstrating the CTIA Cybersecurity Certification Test Plan Version 2.2, Section 3.2.1.

The fresh-device credential is deliberately:

- Username: `admin`
- Password: `admin`

`admin` is treated as a shared **default password**, not a unique factory-set password. It grants access only to mandatory password enrollment. The DUT does not enter normal operation until the password is replaced.

## Start

```bash
docker compose up --build --detach
```

Open <http://127.0.0.1:8080> in the Kali browser.

Check status:

```bash
docker compose ps
curl --fail http://127.0.0.1:8080/healthz
```

Stop the container while retaining device state:

```bash
docker compose down
```

To return to the enrollment state, use **Device → Factory reset** in the Web UI. This is preferable to deleting the Docker volume because it exercises test case 3.2.1.4.

## Reset without logging in

The project includes a host-side equivalent of a router or CPE reset button. From the project directory, run:

```bash
./reset-to-default.sh
```

The command works whether the application container is running or stopped. If the container is stopped, start the pilot afterward:

```bash
docker compose up --detach
```

After the reset, sign in with:

- Username: `admin`
- Password: `admin`

The Web UI will require a new password before returning to normal operation.

The reset is intentionally destructive, like a physical reset button. It performs the same reset routine as **Device → Factory reset** and:

- Invalidates all login sessions.
- Removes every added administrator or operator account.
- Restores the device name and other pilot configuration defaults.
- Restores `admin/admin` and marks the password for mandatory replacement.

Anyone with permission to control the local Docker engine can invoke this reset. Docker access therefore represents physical or administrative access to the pilot device.

The underlying commands are also available if the helper script cannot be used. With the application running:

```bash
docker compose exec -T password-pilot python app.py --factory-reset
```

With the application stopped:

```bash
docker compose run --rm --no-deps password-pilot python app.py --factory-reset
```

## Run automated checks

The production image excludes the tests. Run them in a disposable container using the application image and a temporary data directory:

```bash
docker compose run --rm --no-deps \
  -e CTIA_DATA_DIR=/tmp/ctia-test-data \
  -v "$PWD/tests:/tests:ro" \
  password-pilot python -m unittest discover -s /tests -v
```

## Pilot interpretation

- Repetitive characters means three identical contiguous characters.
- Sequential characters means three contiguous ascending or descending ASCII letters or digits.
- Five failed authentication attempts are permitted in a rolling 60-second window per username and client address. Further attempts return HTTP 429 until the window advances.
- Passwords are hashed using Werkzeug's password-hashing implementation and are never displayed.
- Authentication state is represented by a random opaque cookie; only its SHA-256 digest and CSRF token are stored in SQLite.
- An administrator may create an operator account to exercise the conditional multiple-user and multiple-role cases.

## Scaling to later CTIA sections

The Web UI, SQLite state, authenticated roles, protected device configuration, Docker health check, and persistent volume provide reusable foundations for access control, update management, device identity, audit logging, remote deactivation, and EMS integration pilots.
