package app.sivionmobile.ridon.id.lib;

import java.security.cert.X509Certificate;
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
}
