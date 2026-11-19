
import time
from threading import Lock

from fastapi import HTTPException

MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300
LOCKOUT_SECONDS = 900

login_attempts = {}
lock = Lock()


def check_login_rate_limit(client_ip: str):
    current_time = time.monotonic()

    with lock:
        data = login_attempts.get(client_ip)

        if not data:
            return

        if current_time < data["blocked_until"]:
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Try again later."
            )

        if data["blocked_until"] > 0:
            login_attempts.pop(client_ip, None)
            return

        data["attempts"] = [
            attempt for attempt in data["attempts"]
            if current_time - attempt < WINDOW_SECONDS
        ]


def record_failed_login(client_ip: str):
    current_time = time.monotonic()

    with lock:
        data = login_attempts.setdefault(
            client_ip,
            {"attempts": [], "blocked_until": 0}
        )

        data["attempts"] = [
            attempt for attempt in data["attempts"]
            if current_time - attempt < WINDOW_SECONDS
        ]

        data["attempts"].append(current_time)

        if len(data["attempts"]) >= MAX_ATTEMPTS:
            data["blocked_until"] = current_time + LOCKOUT_SECONDS


def reset_login_attempts(client_ip: str):
    with lock:
        login_attempts.pop(client_ip, None)


# Transaction API rate limiting

TRANSACTION_MAX_REQUESTS = 10
TRANSACTION_WINDOW_SECONDS = 60

transaction_requests = {}


def check_transaction_rate_limit(user_id: int):
    current_time = time.monotonic()

    with lock:
        requests = transaction_requests.get(user_id, [])

        # Keep only requests from the last 60 seconds
        requests = [
            timestamp
            for timestamp in requests
            if current_time - timestamp < TRANSACTION_WINDOW_SECONDS
        ]

        if len(requests) >= TRANSACTION_MAX_REQUESTS:
            transaction_requests[user_id] = requests

            raise HTTPException(
                status_code=429,
                detail="Too many transaction requests. Try again later."
            )

        requests.append(current_time)
        transaction_requests[user_id] = requests
