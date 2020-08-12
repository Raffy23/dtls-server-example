DTLS-Server Examples
====================

This repository contains two DTLS-Server implementations, and a DTLS-Client based on BouncyCastle.
For creating an instance of a server an ecliptic curve key and a `asn1.x509.Certificate` have to be provided. 
The server and the client only use the `DTLSv1.2` protocol with the `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` cipher suit. 

## Socket DTLS-Server
The Socket DTLS-Server is similar to the normal TCP ServerSocket. New connections can be accepted via
the `accept()` method and each connection can be processed by a separate thread.

Example Usage:
```scala
val server: SocketDtlsServer = new SocketDtlsServer(InetAddress.getByName("0.0.0.0"), PORT, certificate, key)

// Loop while the server is running and accept the DTLSClient connections
while ( server.isRunning ) {
  val connection = server.accept()
  // For each new connection create a new thread so they can be processed independently
  // similar to normal TCP Connections
  val t = new Thread(() => {
    while (server.isRunning) {
      val message = connection.read[DTLSMessage]()
      // Do something with the message
    }
  })
  t.start()
}
```

## Stream DTLS-Server
The Event DTLS-Server provides a single queue in which all messages from all clients are pushed. The
server will automatically accept the client connections.  
 
Example Usage:
```scala
private val server = new StreamDtlsServer[DTLSMessage](InetAddress.getByName("0.0.0.0"), PORT, certificate, key)
private val msgQueue  = server.start()

while (server.isRunning) {
  msgQueue.take() match {
    case Connected(address)       => /* A client connected to the server */
    case Disconnected(address)    => /* A client gracefully disconnected from the server */
    case Message(sender, message) => /* Do something with the message */
  }
}
```