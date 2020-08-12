package example

import java.net.InetAddress

import dtls.dto.{ACKMessage, DTLSMessage}
import dtls.server.StreamDtlsServer
import dtls.server.StreamDtlsServer.{Connected, Disconnected, Message}

/**
 * Created by 
 *
 * @author Raphael Ludwig
 * @version 12.08.20
 */
object StreamServerExample extends App {

  // Generate private key and certificate fro the server
  private val (key, certificate) = bootstrap()

  // Create server and create thread to process all messages from clients
  private val server = new StreamDtlsServer[DTLSMessage](InetAddress.getByName("0.0.0.0"), PORT, certificate, key)
  private val msgQueue  = server.start()
  private val serverThread = new Thread(() => {
    while (server.isRunning) {
      msgQueue.take() match {
        case Connected(address)    => println(s"[Server] ${address} connected to server")
        case Disconnected(address) => println(s"[Server] ${address} disconnected from server")
        case Message(sender, data) =>
          println(s"[Server] Message: ${data}")
          server.send(sender, ACKMessage(1))
      }
    }
  })
  serverThread.setDaemon(true)
  serverThread.setName("StreamDTLS-Server")
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
