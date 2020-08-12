import java.net.InetAddress
import java.security.{KeyPair, KeyPairGenerator, SecureRandom, Security}
import java.util.UUID

import dtls.DtlsClient
import dtls.dto.{ACKMessage, StringMessage}
import dtls.util.CertificateUtil
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * @author Raphael Ludwig
 * @version 12.08.20
 */
package object example {
  import ACKMessage.codec
  import StringMessage.codec

  val PORT = 39892

  /**
   * Loads the BouncyCastle Security provider and generates a ecliptic curve key + certificate
   * @return (KeyPair of the Certificate, the signed X509 Certificate)
   */
  def bootstrap(): (KeyPair, Certificate) = {
    Security.addProvider(new BouncyCastleProvider)

    val keyGenerator = KeyPairGenerator.getInstance("ECDSA", "BC")
    keyGenerator.initialize(256, new SecureRandom())

    val key         = keyGenerator.generateKeyPair()
    val certificate = CertificateUtil.generateCertificate(key, UUID.randomUUID().toString)

    (key, certificate)
  }

  /**
   * Create a DTLSClient that sends/receives a sequence of messages
   * @param pinnedKey the public key in the certificate that is trusted
   * @return the DTLSClient instance after sending / receiving a sequence of messages
   */
  def client1(pinnedKey: KeyPair): DtlsClient = {
    val client1 = new DtlsClient(pinnedKey.getPublic.asInstanceOf[BCECPublicKey])
    client1.connect(InetAddress.getLocalHost, PORT)
    client1.write(StringMessage("Hello World"))
    client1.read[ACKMessage]()
    client1.write(StringMessage("Client 1"))
    client1.read[ACKMessage]()
    client1.write(StringMessage("Client 2"))
    client1.read[ACKMessage]()
    client1.write(StringMessage("END"))
    client1.read[ACKMessage]()
    LazyList.from(0).take(100).foreach(i => {
      client1.write(StringMessage(s"Message ${i}"))
      client1.read[ACKMessage]()
    })

    client1
  }

  /**
   * Creates a CTLSClient that sends some messages
   * @param pinnedKey the public key in the certificate that is trusted
   * @return the DTLSClient instance after sending / receiving a sequence of messages
   */
  def client2(pinnedKey: KeyPair): DtlsClient = {
    val client2 = new DtlsClient(InetAddress.getLocalHost, PORT, pinnedKey.getPublic.asInstanceOf[BCECPublicKey])
    client2.write(StringMessage("Hey listen"))
    client2.write(StringMessage("Me2"))
    client2.write(StringMessage("You"))
    client2.write(StringMessage("A"))

    client2
  }

}
