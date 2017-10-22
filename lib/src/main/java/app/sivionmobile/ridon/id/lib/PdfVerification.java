package app.sivionmobile.ridon.id.lib;

import java.util.Date;
import java.util.List;

public class PdfVerification {
  final private List<SignatureVerification> sigs;
  final private String name;
  final private String location;
  final private String reason;
  final private Date date;
  final private Date signedDate;

  public PdfVerification(
      List<SignatureVerification> sigs,
      final String name,
      final String location,
      final String reason,
      final Date date,
      final Date signedDate) {
    this.sigs = sigs;
    this.name = name;
    this.location = location;
    this.reason = reason;
    this.date = date;
    this.signedDate = signedDate;
  }

  public String name() {
    return this.name;
  }

  public String location() {
    return this.location;
  }

  public String reason() {
    return this.reason;
  }

  public Date date() {
    return this.date;
  }

  public Date signedDate() { return this.signedDate; }

  public List<SignatureVerification> signatures() {
    return this.sigs;
  }
}
