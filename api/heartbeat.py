import json
import logging
import time
import uuid

import jwt
import logger
import redis
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS
from jwcrypto import jwk


class SessionQueue:
    def __init__(self, redis_url="redis://localhost:6379", max_session=1):
        self.redis_client = redis.StrictRedis.from_url(redis_url)
        self.max_session = max_session

    def _acquire_lock(self, lock_name, expire_time=10000):
        identifier = str(uuid.uuid4())
        if self.redis_client.set(lock_name, identifier, nx=True, px=expire_time):
            return identifier
        return None

    def _release_lock(self, lock_name, identifier):
        lock_value = self.redis_client.get(lock_name)
        if lock_value and lock_value.decode("utf-8") == identifier:
            self.redis_client.delete(lock_name)
            return True
        return False

    def add_queue(self, user_id, session_id):
        timestamp = int(time.time())
        lock_key = f"{user_id}_lock"
        lock_id = self._acquire_lock(lock_key)

        if lock_id:
            try:
                queue_key = f"{user_id}_queue"
                queue = self.redis_client.lrange(queue_key, 0, -1)

                if len(queue) >= self.max_session:
                    reject_element = self.redis_client.lpop(queue_key)
                    logging.info(f"Removed element: {reject_element}")

                session_data = json.dumps(
                    {"SessionID": session_id, "Timestamp": timestamp}
                )
                self.redis_client.rpush(queue_key, session_data)

                return {
                    "message": f"Added session: {session_id} with timestamp {timestamp}"
                }, 200
            finally:
                self._release_lock(lock_key, lock_id)
        else:
            return {"error": "Failed to acquire lock"}, 500

    def update_queue(self, user_id, session_id):
        timestamp = int(time.time())
        lock_key = f"{user_id}_lock"
        lock_id = self._acquire_lock(lock_key)

        if lock_id:
            try:
                queue_key = f"{user_id}_queue"
                queue = self.redis_client.lrange(queue_key, 0, -1)
                session_found = False

                print(queue)
                for session_data in queue:
                    session = json.loads(session_data)
                    if session["SessionID"] == session_id:
                        self.redis_client.lrem(queue_key, 1, session_data)
                        session_found = True
                        break

                if not session_found:
                    return {"error": f"Session {session_id} not found"}, 403

                session_data = json.dumps(
                    {"SessionID": session_id, "Timestamp": timestamp}
                )
                self.redis_client.rpush(queue_key, session_data)
                logging.info(f"Updated element: {session_data}")
                return {
                    "message": f"Updated session: {session_id} (timestamp {timestamp})"
                }, 200
            finally:
                self._release_lock(lock_key, lock_id)
        else:
            return {"error": "Failed to acquire lock"}, 500


class HeartBeatServer:
    def __init__(self, session_queue):
        self.app = Flask(__name__)
        CORS(self.app)
        self.app.logger.setLevel(logging.INFO)
        self.session_queue = session_queue
        self._setup_routes()
        self._AUTH_SERVER_OPENID_CONFIGURATION_PATH = ".well-known/openid-configuration"
        self._API_ENDPOINT = "http://127.0.0.1:7777"
        self.app.logger.info(f"{session_queue.max_session} is Created")

    def _setup_routes(self):
        self.app.add_url_rule(
            "/add_queue", "add_queue", self._handle_add_queue, methods=["POST"]
        )
        self.app.add_url_rule(
            "/update_queue", "update_queue", self._handle_update_queue, methods=["POST"]
        )
        self.app.add_url_rule(
            "/healthcheck", "health_check", self._handle_health_check, methods=["GET"]
        )

    def _replace_ip_with_domain(self, text):
        return text.replace("127.0.0.1", "auth_server.local")

    def _validate_inclueded_meta(self, access_token):
        try:
            # Decode token without verifying the signature
            payload_json = jwt.decode(
                access_token, options={"verify_signature": False}, algorithms=["RS256"]
            )
            header_json = jwt.get_unverified_header(access_token)

        except Exception as e:
            print(e)
            return None

        try:
            iss = payload_json["iss"]
            AUTH_SERVER_OPENID_CONFIGURATION_URL = (
                iss + self._AUTH_SERVER_OPENID_CONFIGURATION_PATH
            )
            openid_configuration_response = requests.get(
                self._replace_ip_with_domain(AUTH_SERVER_OPENID_CONFIGURATION_URL)
            )
            if not openid_configuration_response.status_code == 200:
                return None
            openid_configurations = openid_configuration_response.json()
            jwks_uri_response = requests.get(
                self._replace_ip_with_domain(openid_configurations["jwks_uri"])
            )

            if not jwks_uri_response.status_code == 200:
                return None
            jwks = jwks_uri_response.json()
            if not jwks.get("keys"):
                return None
            for jwk_json in jwks["keys"]:
                jwk_key = jwk.JWK.from_json(jwk_json)
                if jwk_key.kid == header_json["kid"]:
                    public_pem_key = jwk_key.export_to_pem(
                        private_key=False, password=None
                    )
                    if self._API_ENDPOINT not in payload_json["aud"]:
                        logger.error("Audience does not include:", self._API_ENDPOINT)
                        raise jwt.InvalidTokenError

                    if "heartbeat" not in payload_json["permissions"]:
                        logger.error(
                            "Permissions do not include the required read role"
                        )
                        raise jwt.InvalidTokenError

                    decoded_token = jwt.decode(
                        access_token,
                        public_pem_key,
                        algorithms=[header_json["alg"]],
                        options={"verify_aud": False},
                    )
                    return decoded_token

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def _check_auth_header(self, auth_header):
        if not auth_header:
            return False, jsonify({"message": "Missing token"}), 401

        parts = auth_header.split()
        if parts[0].lower() != "bearer" or len(parts) != 2:
            return False, jsonify({"message": "Invalid token format"}), 401

        access_token = parts[1]
        verified_token = self._validate_inclueded_meta(access_token)
        self.app.logger.info(verified_token)
        if not verified_token:
            return False, jsonify({"message": "Invalid token"}), 401

        return True, jsonify(verified_token), 200

    def _handle_add_queue(self):
        auth_header = request.headers.get("Authorization")
        verified, verified_message, verified_status = self._check_auth_header(
            auth_header
        )
        print(verified_message)
        if verified:
            user_id = request.json.get("user_id")
            session_id = request.json.get("session_id")
            response, queue_status = self.session_queue.add_queue(user_id, session_id)
            return jsonify(response), queue_status
        else:
            return verified_message, verified_status

    def _handle_update_queue(self):
        auth_header = request.headers.get("Authorization")
        verified, verified_message, verified_status = self._check_auth_header(
            auth_header
        )
        print(verified_message)
        if verified:
            user_id = request.json.get("user_id")
            session_id = request.json.get("session_id")
            response, queue_status = self.session_queue.update_queue(
                user_id, session_id
            )
            return jsonify(response), queue_status
        else:
            return verified_message, verified_status

    def _handle_health_check(self):
        return jsonify({"status": "healthy"}), 200

    def run(self):
        self.app.run(host=self.host, port=self.port, debug=self.debug)


if __name__ == "__main__":
    # セッションキューをセットアップ
    session_queue = SessionQueue(redis_url="redis://redis.local:6379", max_session=1)

    # HeartBeatサーバーをセットアップ
    server = HeartBeatServer(session_queue)

    # サーバーを起動
    server.app.run(host="0.0.0.0", port=7777, debug=True)
