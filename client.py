import datetime
import base64
import json

import click
import requests

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_rsa_private_key(key_file):
    with open(key_file, 'r') as key_file:
        private_rsa_key = key_file.read()

    #print("Private key RSA:", private_rsa_key)
    b64data = '\n'.join(private_rsa_key.splitlines()[1:-1])
    #print("B64 data:", b64data)
    derdata = base64.b64decode(b64data)
    #print("DER data:", derdata)
    private_key = serialization.load_der_private_key(
            derdata,
            password=None,
            backend=default_backend()
    )
    #print("Check for RSA private key:", isinstance(private_key, rsa.RSAPrivateKey))
    return private_key


def load_rsa_public_key(key_file):
    with open(key_file, 'r') as key_file:
        public_rsa_key = key_file.read()

    #print("Private key RSA:", public_rsa_key)
    b64data = '\n'.join(public_rsa_key.splitlines()[1:-1])
    #print("B64 data:", b64data)
    derdata = base64.b64decode(b64data)
    #print("DER data:", derdata)
    public_key = serialization.load_der_public_key(
        derdata,
        backend=default_backend()
    )
    #print("Check for RSA public key:", isinstance(public_key, rsa.RSAPublicKey))
    return public_key


def encrypt(cleartext, public_key):
    ciphertext = public_key.encrypt(
        cleartext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        )
    )
    #print("Ciphertext plain:", ciphertext)
    #print("Ciphertext plain length:", len(ciphertext))
    #print("Ciphertext base64:", base64.b64encode(ciphertext))
    #print("Ciphertext base64 length:", len(base64.b64encode(ciphertext)))
    return base64.b64encode(ciphertext)


def decrypt(ciphertext, private_key):
    #print("Ciphertext base64:", ciphertext)
    #print("Ciphertext base64 length:", len(ciphertext))
    #print("Ciphertext plain:", base64.b64decode(ciphertext))
    #print("Ciphertext plain:", len(base64.b64decode(ciphertext)))
    plaintext = private_key.decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        )
    )
    print("Plaintext:", plaintext)
    return plaintext


@click.group()
@click.option('--debug/--no-debug', default=False)
def cli(debug):
    #click.echo('Debug mode is %s' % ('on' if debug else 'off'))
    pass


@cli.command()
@click.option('--rid', default="")
@click.option('--sid', default="")
@click.option('--msg', default="")
def send(rid, sid, msg):
    """Send messages."""
    click.echo("Sending message to %s..." % rid)
    public_key = load_rsa_public_key('{}-public.pem'.format(rid))

    plaintext = {
        'sid': sid,
        'msg': msg,
    }
    data = {
        'rid': rid,
        'msg': encrypt(json.dumps(plaintext), public_key),
    }
    r = requests.post('http://localhost:8080', data=data, timeout=5)
    print("Status code is", r.status_code)


@cli.command()
@click.option('--rid', default="")
def get(rid):
    """Receive messages."""
    click.echo("Retrieving messages...")
    sid = ts = raw = msg = None
    msg_ids = []
    private_key = load_rsa_private_key('{}-private.pem'.format(rid))
    req_get = requests.get('http://localhost:8080', timeout=5)

    for msg_id, msg_content in req_get.json().items():
        if rid == msg_content['rid']:
            msg_ids.append(msg_id)
            click.echo("Found new message...")
            ts = msg_content['ts']
            raw = msg_content['msg']

            click.echo("Message ID: %s" % msg_id)

            value = datetime.datetime.fromtimestamp(ts)

            decrypt(raw, private_key)

            click.echo("Sender ID: %s" % sid)
            click.echo("Timestamp: %s" % value.strftime('%Y-%m-%d %H:%M:%S'))
            click.echo("Message: %s" % msg)

    data = {
        'msg_ids': msg_ids,
    }
    req_del = requests.delete('http://localhost:8080', data=data, timeout=5)
    print(req_del.status_code)


if __name__ == '__main__':
    cli()
