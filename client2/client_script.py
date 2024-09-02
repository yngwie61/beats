import json
import logging
import threading
import time

import requests

# Number of threads
THREAD_COUNT = 100

# Target URL
url_add = "http://beat.local:5000/add_queue"
url_update = "http://beat.local:5000/update_queue"
logging.basicConfig(level=logging.INFO)


def logger_response(status: int, method: str, data: dict):
    if status == 200:
        logging.info(f"Status Code: {status}, Complete Method: {method}, Query: {data}")
    elif status == 403:
        logging.warning(
            f"Status Code: {status}, Failed Method: {method}, Query: {data}"
        )
    else:
        logging.critical(
            f"Status Code: {status}, Error Method: {method}, Query: {data}"
        )


def make_requests(thread_num):
    user_id = thread_num
    # Parameters
    headers = {"content-type": "application/json"}
    params = [
        {"user_id": f"{user_id}", "session_id": "11"},
        {"user_id": f"{user_id}", "session_id": "12"},
        {"user_id": f"{user_id}", "session_id": "13"},
        {"user_id": f"{user_id}", "session_id": "14"},
        {"user_id": f"{user_id}", "session_id": "15"},
    ]

    # Make add_queue requests
    for param in params:
        r = requests.post(url_add, data=json.dumps(param), headers=headers)
        logger_response(status=r.status_code, method=url_add, data=param)

    # Make update_queue requests with 100ms intervals
    for _ in range(4):
        r = requests.post(url_update, data=json.dumps(params[2]), headers=headers)
        logger_response(status=r.status_code, method=url_update, data=params[2])
        time.sleep(0.1)

    # Make update_queue requests with 100ms intervals
    r = requests.post(url_update, data=json.dumps(params[1]), headers=headers)
    logger_response(status=r.status_code, method=url_update, data=params[1])


# Create threads
threads = []
for thread_num in range(THREAD_COUNT):
    thread = threading.Thread(target=make_requests, args=(thread_num,))
    threads.append(thread)
    thread.start()

# Wait for all threads to finish
for thread in threads:
    thread.join()
