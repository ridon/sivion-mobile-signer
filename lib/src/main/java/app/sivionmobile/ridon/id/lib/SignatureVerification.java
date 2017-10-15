package app.sivionmobile.ridon.id.lib;

import java.security.cert.X509Certificate;

public class SignatureVerification {
  private boolean verified = false;
  private boolean trusted = false;
  final X509Certificate certificate;

  public SignatureVerification(final X509Certificate cert, boolean verified, boolean trusted) {
    this.certificate = cert;
    this.verified = verified;
    this.trusted = trusted;
  }

  public boolean isVerified() {
    return verified;
  }

  public boolean isTrusted() {
    return trusted;
  }
}
