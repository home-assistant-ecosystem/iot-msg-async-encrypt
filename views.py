import asyncio
import hashlib
import time
import os

import random

from aiohttp import web

messages = {}


def random_data():
    msg_id = hashlib.sha256(b'\x00' + os.urandom(12) + b'\x00').hexdigest()
    messages[msg_id] = {
        'ts': time.time(),
        'rid': str(random.randrange(0, 10000)),
        'msg': hashlib.sha512(b'\x00' + os.urandom(12) + b'\x00').hexdigest(),
    }


async def index(request):
    return web.json_response(messages)


@asyncio.coroutine
def post_handler(request):
    random_data()
    body = yield from request.post()
    msg_id = hashlib.sha256(b'\x00' + os.urandom(12) + b'\x00').hexdigest()
    messages[msg_id] = {
        'ts': time.time(),
        'rid': body['rid'],
        'msg': body['msg'],
    }
    return web.Response(text="post")


@asyncio.coroutine
def delete_handler(request):
    body = yield from request.post()
    for key, msg_id in body.items():
        if msg_id in messages.keys():
            del messages[msg_id]

    return web.Response(text="delete")
