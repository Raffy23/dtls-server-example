package dtls

import java.security.KeyPair

import org.bouncycastle.crypto.params.{ECDomainParameters, ECPrivateKeyParameters}
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.bouncycastle.tls.crypto.impl.bc.{BcTlsCertificate, BcTlsCrypto, BcTlsECDSASigner}
import org.bouncycastle.tls._
import org.bouncycastle.asn1.x509

/**
 * Created by 
 *
 * @author Raphael Ludwig
 * @version 10.08.20
 */
package object server {

  protected[server] val MIN_IP_OVERHEAD = 20
  protected[server] val MAX_IP_OVERHEAD: Int = MIN_IP_OVERHEAD + 64
  protected[server] val UDP_OVERHEAD = 8

  protected[server] def server(key: KeyPair, certificate: x509.Certificate)(implicit crypto: BcTlsCrypto): DefaultTlsServer = new DefaultTlsServer(crypto) {
    private var defaultSigner: DefaultTlsCredentialedSigner = _

    override def init(context: TlsServerContext): Unit = {
      super.init(context)
      defaultSigner = new DefaultTlsCredentialedSigner(
        new TlsCryptoParameters(context),
        new BcTlsECDSASigner(crypto, {
          val privateKey = key.getPrivate.asInstanceOf[BCECPrivateKey]
          val params     = privateKey.getParameters

          new ECPrivateKeyParameters(privateKey.getD, new ECDomainParameters(params.getCurve, params.getG, params.getN))
        }),
        new Certificate(Array(new BcTlsCertificate(crypto, certificate))),
        new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa)
      )
    }

    override def getECDSASignerCredentials: TlsCredentialedSigner = defaultSigner

    override def getSupportedVersions: Array[ProtocolVersion] = Array(ProtocolVersion.DTLSv12)

    override def getSupportedCipherSuites: Array[Int] = Array(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)

  }


}
