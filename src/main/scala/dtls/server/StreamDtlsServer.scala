package dtls.server

import java.net.{InetAddress, InetSocketAddress, SocketAddress}
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.security.{KeyPair, SecureRandom}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicInteger}
import java.util.concurrent._

import dtls.util.codec.{Codec, Decoder, Encoder}
import org.bouncycastle.asn1.x509
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.bouncycastle.tls._

import scala.collection.mutable
import scala.util.Try

/**
 * Created by 
 *
 * @author Raphael Ludwig
 * @version 09.08.20
 */
class StreamDtlsServer[T](bind: InetAddress, port: Int, certificate: x509.Certificate, masterKey: KeyPair, mtu: Int = 1500)(implicit codec: Codec[T]) extends AutoCloseable {
  import StreamDtlsServer._

  private implicit val crypto: BcTlsCrypto = new BcTlsCrypto(new SecureRandom())
  private val protocol = new DTLSServerProtocol()

  private val channel     = DatagramChannel.open()
  private val running     = new AtomicBoolean(true)
  private val connections = mutable.Map.empty[SocketAddress, DtlsConnectionContext[T]]

  private val tCounter    = new AtomicInteger(0)
  private val executor    = Executors.newCachedThreadPool((runnable: Runnable) => {
    val thread = new Thread(runnable)
    thread.setName("NIO DTLS-Server Worker-" + tCounter.getAndIncrement())
    thread.setDaemon(true)
    thread
  })
  private var pktReceiver: Thread = _

  def start(): LinkedBlockingQueue[Event[T]] = {
    val msgQueue  = new LinkedBlockingQueue[Event[T]]()
    val context   = ServerContext(channel, executor, crypto, protocol, msgQueue, mtu, executor)
    channel.socket().bind(new InetSocketAddress(bind, port))

    pktReceiver = new Thread(() => {
      val recvBuffer = ByteBuffer.allocate(mtu)
      while( running.get() ) {
        recvBuffer.clear()
        val peerAddress = channel.receive(recvBuffer)
        val connection  = connections.getOrElseUpdate(peerAddress,  new DtlsConnectionContext[T](peerAddress, server(masterKey, certificate), context, { () =>
          msgQueue.add(Disconnected(peerAddress))
          connections.remove(peerAddress)
        }))

        recvBuffer.flip()
        connection.process(recvBuffer).foreach(content => msgQueue.add(Message(peerAddress, content)))
      }
    }, s"DTLS-Server ${new InetSocketAddress(bind, port)} (Packet receiver)")
    pktReceiver.setDaemon(true)
    pktReceiver.start()

    msgQueue
  }

  /**
   * @return true if the server is running and able to process packets, false otherwise
   */
  def isRunning: Boolean = running.get()

  def send(to: SocketAddress, data: T): Unit = {
    connections(to).send(data)
  }

  override def close(): Unit = {
    executor.shutdown()
    channel.close()
  }

}
object StreamDtlsServer {

  trait Event[T]
  case class Connected[T](address: SocketAddress) extends Event[T]
  case class Disconnected[T](address: SocketAddress) extends Event[T]
  case class Message[T](sender: SocketAddress, data: T) extends Event[T]

  private case class ServerContext[T](channel: DatagramChannel, executor: ExecutorService,
                                      crypto: BcTlsCrypto, protocol: DTLSServerProtocol,
                                      decodedQueue: LinkedBlockingQueue[Event[T]], mtu: Int,
                                      executorService: ExecutorService) {
    val receiveLimit: Int = mtu - MIN_IP_OVERHEAD - UDP_OVERHEAD
    val sendLimit: Int    = mtu - MAX_IP_OVERHEAD - UDP_OVERHEAD
  }

  private trait DtlsPacketHandler[T] {
    def process(packet: ByteBuffer)(implicit decoder: Decoder[T]): Option[T]
    def send(data: T)(implicit encoder: Encoder[T]): Unit
  }

  private class DtlsConnectionContext[T](address: SocketAddress, sslServer: TlsServer, context: ServerContext[T], close: () => Unit) extends DtlsPacketHandler[T] {

    private var handler: DtlsPacketHandler[T] = new DtlsClientHelloHandler()
    private val datagramSender = new DatagramSender {
      override def getSendLimit: Int = context.sendLimit
      override def send(buf: Array[Byte], off: Int, len: Int): Unit = {
        if (len > getSendLimit)
          throw new TlsFatalAlert(AlertDescription.internal_error)

        val buffer = ByteBuffer.wrap(buf)
        buffer.position(off)
        buffer.limit(off + len)

        context.channel.send(buffer, address)
      }
    }
    private val transport = new CustomDatagramTransport()

    private class DtlsClientHelloHandler() extends DtlsPacketHandler[T] {
      private val verifier = new DTLSVerifier(context.crypto)

      override def process(packet: ByteBuffer)(implicit decoder: Decoder[T]): Option[T] = {

        val request = verifier.verifyRequest(
          address.asInstanceOf[InetSocketAddress].getAddress.getAddress,
          packet.array(), packet.position(), packet.limit(),
          datagramSender
        )

        if (request != null) {
          val handshakeHandler = new DtlsHandshakeHandler(request)
          handler = handshakeHandler

          context.executorService.submit(handshakeHandler)
        }

        None
      }

      override def send(data: T)(implicit encoder: Encoder[T]): Unit = ???
    }

    private class DtlsHandshakeHandler(request: DTLSRequest)(implicit decoder: Decoder[T]) extends DtlsPacketHandler[T] with Runnable {

      override def process(packet: ByteBuffer)(implicit decoder: Decoder[T]): Option[T] = {
        val clonedBuffer = packet.duplicate()

        if (!transport.receiveQueue.offer(clonedBuffer)) {
          transport.receiveQueue.remove()
          transport.receiveQueue.add(clonedBuffer)
        }

        None
      }

      override def run(): Unit = {
        handler = new UserPayloadHandler(context.protocol.accept(sslServer, transport, request))

        context.decodedQueue.add(Connected(address))
        transport.useQueueAsSource = false

        // Drain the messages in the queue and process them
        transport.receiveQueue.forEach((t: ByteBuffer) =>
          handler.process(t).foreach(result => context.decodedQueue.add(Message(address, result)))
        )
      }

      override def send(data: T)(implicit encoder: Encoder[T]): Unit = ???
    }

    private class CustomDatagramTransport(bufferSize: Int = 16) extends DatagramTransport {
      val receiveQueue = new ArrayBlockingQueue[ByteBuffer](bufferSize)
      var buffer: ByteBuffer = _
      var useQueueAsSource = true

      override def getReceiveLimit: Int = context.receiveLimit

      override def receive(buf: Array[Byte], off: Int, len: Int, waitMillis: Int): Int = {
        if (useQueueAsSource) {
          val buffer = receiveQueue.poll(waitMillis, TimeUnit.MILLISECONDS)

          if (buffer == null)
            return 0

          buffer.get(buf, off, Math.min(buffer.limit(), len)).position()
        } else {
          buffer.get(buf, off, Math.min(buffer.limit(), len)).position()
        }
      }

      override def getSendLimit: Int = context.sendLimit

      override def send(buf: Array[Byte], off: Int, len: Int): Unit = datagramSender.send(buf, off, len)

      override def close(): Unit = DtlsConnectionContext.this.close()
    }

    private class UserPayloadHandler(server: DTLSTransport) extends DtlsPacketHandler[T] {
      override def process(packet: ByteBuffer)(implicit decoder: Decoder[T]): Option[T] = {

        transport.buffer = packet
        val r = Try(server.receive(transport.buffer.array(), 0, transport.buffer.limit(), 0)).getOrElse(-1)
        if (r > 0) {
          transport.buffer.limit(r)
          transport.buffer.position()
          return Some(decoder.decode(transport.buffer))
        }

        if (r == -1)
          close()

        None
      }

      override def send(data: T)(implicit encoder: Encoder[T]): Unit = {
        val buffer = encoder.encode(data)
        server.send(buffer.array(), buffer.position(), buffer.limit())
      }
    }

    def process(packet: ByteBuffer)(implicit decoder: Decoder[T]): Option[T] = {
      handler.process(packet)
    }

    override def send(data: T)(implicit encoder: Encoder[T]): Unit = handler.send(data)
  }
}
