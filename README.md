asio-packet-stream

A C++ library I made to make my life easier for async, non-blocking network I/O using asio
the main idea was something to let me send / process packets with almost no boilerplate. 

It’s heavily inspired by Source Engine macros for defining and processing packets, but I adapted it for my own projects, including things like large file streaming, chained packets, and certificate generation packets (WIP).
The idea is to have a fast, flexible, and cross-platform packet system. 

The server is made for Linux, and the client on Windows.

It uses a clean OOP based codestyle, with virtual functions such as OnConnect, OnReceive, Multicast, RemoveSession, VerifyCertificate, OnError. usage in client/server.cpp
and with 

TODO: 
1. Adding proper cerficate generation for clients.
2. Full client-side TLS certificate verification (pinning / CA validation)
3. Optional paywall / client signup system integrated with certificate issuance
4. Improved packet validation and error handling for corrupted or malicious ones
5. Heartbeat system and features to detect malpractice on the clientside / detect potential bytepatching or abnormal behavior
6. Other leak preventation security measures 
