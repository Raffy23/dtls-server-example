package example

import java.net.InetAddress

import dtls.dto.{ACKMessage, StringMessage}
import dtls.server.SocketDtlsServer

/**
 * Example usage of the DtlsServer / DtlsClient implementations
 *
 * @author Raphael Ludwig
 * @version 08.08.20
 */
object SocketServerExample extends App {
  import ACKMessage.codec
  import StringMessage.codec

  // Generate private key and certificate fro the server
  private val (key, certificate) = bootstrap()

  // Create the server and launch the accept() thread
  private val server: SocketDtlsServer = new SocketDtlsServer(InetAddress.getByName("0.0.0.0"), PORT, certificate, key)
  private val serverThread = new Thread(() => {
    println("[Server] Thread started ...")

    // Loop while the server is running and accept the DTLSClient connections
    while ( server.isRunning ) {
      val connection = server.accept()

      println("[Server] New Connection!")
      // For each new connection create a new thread so they can be processed independently
      // similar to normal TCP Connections
      val t = new Thread(() => {

        while (server.isRunning) {
          val message = connection.read[StringMessage]()
          println(s"[Server] Payload: ${message}")
          connection.write(ACKMessage(1))
        }

      })
      t.setName(s"DTLS-Connection Handler ${connection.socketAddress}")
      t.setDaemon(true)
      t.start()
    }

  })
  serverThread.setName("SocketDTLS-Server (Accept connections thread)")
  serverThread.setDaemon(true)
  serverThread.start()

  private val c1 = client1(key)
  private val c2 = client2(key)

  println("Press ENTER to exit ...")
  System.in.read()
  c1.close()
  c2.close()

  // Close server
  server.close()
  serverThread.interrupt()

}
