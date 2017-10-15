package app.sivionmobile.ridon.id.lib;

import android.support.annotation.NonNull;

import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cms.CMSException;
import org.spongycastle.cms.CMSProcessableByteArray;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.SignerInformation;
import org.spongycastle.cms.SignerInformationStore;
import org.spongycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.spongycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.util.Iterable;
import org.spongycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

public class P7Verifier {
  final CMSSignedData signedData;

  public P7Verifier(final byte[] signature, final byte[] data) throws CMSException {
    signedData = new CMSSignedData(new CMSProcessableByteArray(data), new ByteArrayInputStream(signature));
  }

  public P7Verifier(final byte[] signature, final InputStream data) throws CMSException {
    signedData = new CMSSignedData(new P7InputStream(data), new ByteArrayInputStream(signature));
  }

  public P7Verifier(final byte[] signature) throws CMSException {
    signedData = new CMSSignedData(new ByteArrayInputStream(signature));
  }


  public List<SignatureVerification> verify() throws CertificateException, OperatorCreationException, CMSException {
    Store certs = signedData.getCertificates();
    SignerInformationStore signers = signedData.getSignerInfos();
    Collection c = signers.getSigners();
    Iterator it = c.iterator();
    List<SignatureVerification> ret = new ArrayList<SignatureVerification>();
    while (it.hasNext()) {
      SignerInformation signer = (SignerInformation) it.next();
      Collection certCollection = certs.getMatches(signer.getSID());
      Iterator certIt = certCollection.iterator();
      X509CertificateHolder holder = (X509CertificateHolder) certIt.next();
      X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);

      boolean trusted = false;
      boolean verified = false;
      if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert))) {
        verified = true;
      }
      SignatureVerification v = new SignatureVerification(cert, verified, trusted);
      ret.add(v);

    }
    return ret;
  }
}
