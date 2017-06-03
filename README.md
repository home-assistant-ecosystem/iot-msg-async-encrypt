# Send and receive encrypted messages with Home Assistant

This little project is a prototype for sending and receiving messages which
are protected by an asymetrical encryption.

The sender using the public key of the recipient to encrypt the message and
sends it to intermediary system. This system could be anything, here is a 
very simple RESTful API which is acting as storage location from the messages.
[Home Assistent](https://home-assistant.io/) which is the consumer of the
messages is pulling the messages from the intermediary system, decrypting it,
and exposing the data as sensor values.

The purpose is to be able to collect messages from remote locations in a 
secure way when there is no other option available beside GET and POST.

Don't use this in production.

## Requirements

The following Python modules are needed to run this code:

- aiohttp
- click
- cryptography
- requests

## Usage

You need to create the keys manually as key distribution is not available:

Private key:

```bash
$ openssl genrsa -out key-private.pem 4096
```

Public key:

```bash
$ openssl rsa -in key-private.pem -outform PEM -pubout -out key-public.pem
```

Keep in mind that you need key for every party which is participating in the 
communication.

Start the server part:

```bash
$ python3 server.py
```

Use the command-line client to send and receive messages:

```bash
$ python3 client.py 
Usage: client.py [OPTIONS] COMMAND [ARGS]...

Options:
  --debug / --no-debug
  --help                Show this message and exit.

Commands:
  get   Receive messages.
  send  Send messages.
```

Visit http://127.0.0.1:8080 to see the available messages.


## License

This project is licensed under ASL 2.0, for more details check LICENSE.
