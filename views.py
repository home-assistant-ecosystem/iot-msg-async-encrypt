import hashlib
import time
import os

import random

from aiohttp import web

messages = {}


def random_data():
    """Create random messages."""
    msg_id = hashlib.sha256(b'\x00' + os.urandom(12) + b'\x00').hexdigest()
    messages[msg_id] = {
        'ts': time.time(),
        'rid': str(random.randrange(0, 10000)),
        'msg': hashlib.sha512(b'\x00' + os.urandom(12) + b'\x00').hexdigest(),
    }


async def index(request):
    """Serve the content for the index."""
    return web.json_response(messages)


async def post_handler(request):
    """Handle the HTTP POST requests."""
    random_data()
    body = await request.post()
    msg_id = hashlib.sha256(b'\x00' + os.urandom(12) + b'\x00').hexdigest()
    messages[msg_id] = {
        'ts': time.time(),
        'rid': body['rid'],
        'msg': body['msg'],
    }
    return web.Response(text='post')


async def delete_handler(request):
    """Handle the HTTP DELETE requests."""
    body = await request.post()
    for key, msg_id in body.items():
        if msg_id in messages.keys():
            del messages[msg_id]

    return web.Response(text='delete')
