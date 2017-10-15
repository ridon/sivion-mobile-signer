package app.sivionmobile.ridon.id.lib;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.security.KeyStore;
import java.security.Security;

import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaCertStore;
import org.spongycastle.cms.CMSException;
import org.spongycastle.cms.CMSProcessableByteArray;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.CMSSignedDataGenerator;
import org.spongycastle.cms.CMSTypedData;
import org.spongycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.spongycastle.util.Store;

public class P7Signer {
  KeyStore store;
  private boolean detached = false;
  CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
  private static final String ALGO = "SHA256withRSA";
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public void addSigner(String alias) throws KeyStoreException, CertificateEncodingException, UnrecoverableEntryException, NoSuchAlgorithmException, OperatorCreationException, CMSException, IOException {
    Certificate[] chain = (Certificate[]) store.getCertificateChain(alias);
    final List<Certificate> list = new ArrayList<Certificate>();

    for (int i = 0, length = chain == null ? 0 : chain.length; i < length; i++) {
      list.add(chain[i]);
    }

    Store certStore = new JcaCertStore(list);
    Certificate cert = store.getCertificate(alias);

    org.spongycastle.asn1.x509.Certificate x509cert = org.spongycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(cert.getEncoded()));

    KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) store.getEntry(alias, null);
    PrivateKey privKey = keyEntry.getPrivateKey();

    ContentSigner signer = new JcaContentSignerBuilder(ALGO).build(privKey);

    generator.addSignerInfoGenerator(
        new JcaSignerInfoGeneratorBuilder(
            new JcaDigestCalculatorProviderBuilder().build()).build(signer, new X509CertificateHolder(x509cert)));
    generator.addCertificates(certStore);

  }

  private CMSSignedData signData(CMSTypedData data) throws CMSException {
    CMSSignedData ret = generator.generate(data, !detached);
    return ret;
  }

  public byte[] sign(final byte[] data) throws IOException, CMSException {
    CMSTypedData cmsData = new CMSProcessableByteArray(data);
    CMSSignedData signedData = signData(cmsData);
    return signedData.getEncoded();

  }

  public byte[] sign(P7InputStream data) throws IOException, CMSException {
    CMSSignedData signedData = signData(data);
    return signedData.getEncoded();
  }

  public P7Signer(final KeyStore store) {
    this.store = store;
  }
  public P7Signer(final KeyStore store, boolean detached) {
    this.detached = detached;
  }


}
