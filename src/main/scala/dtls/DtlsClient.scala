package dtls

import java.io.IOException
import java.net.{DatagramSocket, InetAddress}
import java.nio.ByteBuffer
import java.security.{SecureRandom, Signature}

import dtls.util.codec.{Decoder, Encoder}
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.tls.crypto.impl.bc.{BcTlsCertificate, BcTlsCrypto}
import org.bouncycastle.tls.{TlsAuthentication, _}

import scala.util.Try

/**
 * A DTLS-Client implementation that provides simple read/write methods to send/receive encoded
 * data packets over a DTLS connection. This client is able to connect only to servers that provide
 * a ECDSA certificate that uses SHA256 for signing, otherwise certification checks will fail.
 *
 * @author Raphael Ludwig
 * @version 08.08.20
 */
class DtlsClient(pkServer: BCECPublicKey, mtu: Int) extends AutoCloseable {
  import DtlsClient._

  private val crypto    = new BcTlsCrypto(new SecureRandom())
  private val socket    = new DatagramSocket()
  private val protocol  = new DTLSClientProtocol()

  private val tlsAuth = new TlsAuthentication {

    // Only accept pinned public key in server certificate ...
    override def notifyServerCertificate(serverCertificate: TlsServerCertificate): Unit = {
      if (!verifyCertificate(serverCertificate, pkServer))
        throw new TlsFatalAlert(AlertDescription.bad_certificate)
    }

    override def getClientCredentials(certificateRequest: CertificateRequest): TlsCredentials = null
  }
  private val client  = new DefaultTlsClient(crypto) {

    override def getAuthentication: TlsAuthentication = tlsAuth

    override def getProtocolVersions: Array[ProtocolVersion] = Array(ProtocolVersion.DTLSv12)

    override def getSupportedCipherSuites: Array[Int] = Array(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)

  }

  // Connect and start handshake
  private var connection: DTLSTransport = _

  def this(pkServer: BCECPublicKey) {
    this(pkServer, 1500)
  }

  def this(address: InetAddress, port: Int, pkServer: BCECPublicKey, mtu: Int = 1500) {
    this(pkServer, mtu)
    this.connect(address, port)
  }

  /**
   * Connect to the specified address and port, after this call the DTLS handshake has been performed
   * and the connection is read to read/write data packets.
   *
   * @param address target address that should be connected to
   * @param port target port that should be connected to
   */
  def connect(address: InetAddress, port: Int): Unit = {
    socket.connect(address, port)
    connection = protocol.connect(client, new UDPTransport(socket, mtu))
  }

  /**
   * Sends the class provided over the socket to the other end. The encoder will automatically
   * encode the class into the packet representation
   *
   * @param packet a class that should be send over
   * @param encoder implicit encoder that encodes the class T
   * @tparam T class which should be encoded to a packet
   */
  def write[T](packet: T)(implicit encoder: Encoder[T]): Unit = {
    assert(connection != null)

    val data = encoder.encode(packet)
    connection.send(data.array(), 0, data.capacity())
  }

  /**
   * Waits for a packet that is automatically decoded by the provided decoder to the class T,
   * this method does block until data is available.
   *
   * @param decoder an implicit decoder for the class T
   * @tparam T class in which the packet should be decoded to
   * @throws RuntimeException if no byte where read from the socket
   * @return the decoded packet
   */
  @throws[IOException]
  def read[T]()(implicit decoder: Decoder[T]): T = {
    assert(connection != null)

    val buffer = Array.ofDim[Byte](mtu)
    val len = connection.receive(buffer, 0, mtu, SOCKET_WAIT_TIME)

    if (len > 0 )
      return decoder.decode(ByteBuffer.wrap(buffer))

    throw new IOException("Buffer size is < 0")
  }

  /**
   * Closes the socket and the connection, no further read/write function calls are possible
   */
  override def close(): Unit = {
    assert(connection != null)
    connection.close()
    socket.close()
  }
}
object DtlsClient {

  protected val SOCKET_WAIT_TIME = 60_000 // ms

  /**
   * Check if the certificate is valid (signature) and if the subject key is equal to the provided
   * server key.
   *
   * @param certificate the certificate that should be checked
   * @param serverKey the pinned server key
   * @return true if the certificate is acceptable, false otherwise
   */
  protected def verifyCertificate(certificate: TlsServerCertificate, serverKey: BCECPublicKey): Boolean = {
    val tlsCert = certificate.getCertificate.getCertificateAt(0)

    // Only accept pinned public key from server
    if (!serverKey.getQ.equals(tlsCert.asInstanceOf[BcTlsCertificate].getPubKeyEC.getQ)) {
      return false
    }

    // Certificate must be signed with SHA256withECDSA
    if (tlsCert.getSigAlgOID != "1.2.840.10045.4.3.2") {
      return false
    }

    val cert    = BcTlsCertificate.parseCertificate(tlsCert.getEncoded)

    // Verify Certificate
    val ecdsaVerifier = Signature.getInstance("SHA256withECDSA")
    ecdsaVerifier.initVerify(serverKey)
    ecdsaVerifier.update(cert.getTBSCertificate.getEncoded(ASN1Encoding.DER))
    Try(ecdsaVerifier.verify(cert.getSignature.getBytes)).getOrElse(false)
  }

}