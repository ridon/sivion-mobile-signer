package app.sivionmobile.ridon.id.lib;

import org.spongycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Date;

public class SignatureVerification {
  private boolean verified = false;
  private boolean trusted = false;
  private final X509Certificate certificate;
  private final Date date;

  public SignatureVerification(final X509Certificate cert, final boolean verified, final boolean trusted, final Date date) {
    this.certificate = cert;
    this.verified = verified;
    this.trusted = trusted;
    this.date = date;
  }

  public SignatureVerification(final X509Certificate cert, final boolean verified, final boolean trusted) {
    this(cert, verified, trusted, null);
  }

  public boolean isVerified() {
    return verified;
  }

  public boolean isTrusted() {
    return trusted;
  }

  public String serialNumber() {
    return certificate.getSerialNumber().toString();
  }

  public String issuer() {
    return certificate.getIssuerDN().toString();
  }

  public String subject() {
    return certificate.getSubjectDN().toString();
  }

  public String validity() {
    return certificate.getNotBefore().toLocaleString() + " - " + certificate.getNotAfter().toLocaleString();
  }

  public String publicKey() {
    return certificate.getPublicKey().getAlgorithm().toString() + "/" + ((RSAKey) certificate.getPublicKey()).getModulus().bitLength() + " bit";
  }

  public String algorithm() {
    return certificate.getSigAlgName().toString();
  }

  public String fingerprint() {
    MessageDigest md = null;
    try {
      md = MessageDigest.getInstance("SHA-1");
      byte[] der = certificate.getEncoded();
      md.update(der);
      byte[] digest = md.digest();
      return Hex.toHexString(digest);
    } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
      return "N/A";
    }

  }
}
