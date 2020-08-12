package dtls.util

import java.math.BigInteger
import java.security.cert.X509Certificate
import java.security.{KeyPair, PublicKey}
import java.time.Instant
import java.util.{Date, Locale}

import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.{X509ExtensionUtils, X509v3CertificateBuilder}
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.operator.bc.{BcDigestCalculatorProvider, BcECContentSignerBuilder}
import org.bouncycastle.operator.{DefaultDigestAlgorithmIdentifierFinder, DefaultSignatureAlgorithmIdentifierFinder}

/**
 * Utility class that helps generating and singing ECDSA certificates
 *
 * @author Raphael Ludwig
 * @version 08.08.20
 */
object CertificateUtil {

  val SIGNATURE_ALGORITHM = "SHA256withECDSA"
  val DIGEST_ALGORITHM    = "SHA256"

  /**
   * Generates a Certificate signed with an ECDSA key
   *
   * @param key must be a implementation that supports ECDSA
   * @param issuer name of the issuer / subject without the CN= part
   * @param from validity start date
   * @param to validity end date
   * @return the Certificate
   */
  def generateCertificate(key: KeyPair, issuer: String, from: Date = yesterday(), to: Date = in30Days()): Certificate = {
    generateCertificateHolder(key, issuer, from, to).toASN1Structure
  }

  def generateJavaCertificate(key: KeyPair, issuer: String, from: Date = yesterday(), to: Date = in30Days()): X509Certificate = {
    new JcaX509CertificateConverter().getCertificate(generateCertificateHolder(key, issuer, from, to))
  }

  private def generateCertificateHolder(key: KeyPair, issuer: String, from: Date = yesterday(), to: Date = in30Days()) = {
    val name = new X500Name("CN=" + issuer)
    val certGenerator = new X509v3CertificateBuilder(
      name,
      BigInteger.valueOf(Instant.now.toEpochMilli),
      from, // yesterday
      to, // 30 days
      Locale.GERMANY,
      name,
      SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(key.getPublic.getEncoded))
    )
      .addExtension(Extension.authorityKeyIdentifier, false, hashPublicKeyFor(key.getPublic) { case (u, k) => u.createAuthorityKeyIdentifier(k) })
      .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
      .addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.keyEncipherment))
      .addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(Array[KeyPurposeId](KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth)))
      .addExtension(Extension.subjectKeyIdentifier, false, hashPublicKeyFor(key.getPublic) { case (u, k) => u.createSubjectKeyIdentifier(k) })

    val contentSigner = new BcECContentSignerBuilder(
      new DefaultSignatureAlgorithmIdentifierFinder().find(SIGNATURE_ALGORITHM),
      new DefaultDigestAlgorithmIdentifierFinder().find(DIGEST_ALGORITHM)
    ).build(PrivateKeyFactory.createKey(key.getPrivate.getEncoded))

    certGenerator.build(contentSigner)
  }

  protected def hashPublicKeyFor[T](key: PublicKey)(f: (X509ExtensionUtils, SubjectPublicKeyInfo) => T): T = {
    val publicKeyInfo = SubjectPublicKeyInfo.getInstance(key.getEncoded)
    val digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1))

    f(new X509ExtensionUtils(digCalc), publicKeyInfo)
  }

  protected def yesterday(): Date = new Date(System.currentTimeMillis() -      24 * 60 * 60 * 1000)
  protected def in30Days(): Date  = new Date(System.currentTimeMillis() + 30 * 24 * 60 * 60 * 1000)

}
