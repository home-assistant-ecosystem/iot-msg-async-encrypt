# Send and receive encrypted messages for Home Assistant

This little project is a prototype for sending and receiving messages which
are protected by an asymetrical encryption.

The sender using the public key of the recipient to encrypt the message and
sends it to intermediary system. This system could be anything, here is a 
very simple RESTful API which is acting as storage location from the messages.
Home Assistent which is the consumer of the messages is pulling the messages
from the intermediary system, decrypting it, and exposing the data as sensor
values.

The purpose is to be able to collect messages from remote locations in a 
secure way when there is no other option available beside GET and POST.

Don't use this in production.
