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
import java.util.Collection;
import java.util.List;
import java.security.KeyStore;
import java.security.Security;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.DERSet;
import org.spongycastle.asn1.cms.Attribute;
import org.spongycastle.asn1.cms.AttributeTable;
import org.spongycastle.asn1.cms.Attributes;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaCertStore;
import org.spongycastle.cms.CMSException;
import org.spongycastle.cms.CMSProcessableByteArray;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.CMSSignedDataGenerator;
import org.spongycastle.cms.CMSTypedData;
import org.spongycastle.cms.SignerInformation;
import org.spongycastle.cms.SignerInformationStore;
import org.spongycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.spongycastle.tsp.TSPException;
import org.spongycastle.util.Store;

public class P7Signer {
  KeyStore store;
  final private TsaClient tsaClient;
  private boolean detached = true;
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

  private SignerInformation replaceSigner(SignerInformation signer)
      throws IOException, TSPException, NoSuchAlgorithmException {
    AttributeTable unsignedAttributes = signer.getUnsignedAttributes();

    ASN1EncodableVector vector = new ASN1EncodableVector();
    if (unsignedAttributes != null)
    {
      vector = unsignedAttributes.toASN1EncodableVector();
    }

    byte[] token = tsaClient.getToken(signer.getSignature());
    ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
    ASN1Encodable signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Primitive.fromByteArray(token)));

    vector.add(signatureTimeStamp);
    Attributes signedAttributes = new Attributes(vector);

    SignerInformation newSigner = SignerInformation.replaceUnsignedAttributes(
        signer, new AttributeTable(signedAttributes));

    return newSigner;
  }

  private CMSSignedData signData(CMSTypedData data) throws CMSException, TSPException, NoSuchAlgorithmException, IOException {
    CMSSignedData ret = generator.generate(data, !detached);
    if (tsaClient != null) {
      SignerInformationStore signerStore = ret.getSignerInfos();
      List<SignerInformation> newSigners = new ArrayList<SignerInformation>();
      for (SignerInformation signer : (Collection<SignerInformation>) signerStore.getSigners()) {
        newSigners.add(replaceSigner(signer));
      }
      ret = CMSSignedData.replaceSigners(ret, new SignerInformationStore(newSigners));
    }
    return ret;
  }

  public byte[] sign(final byte[] data) throws IOException, CMSException, TSPException, NoSuchAlgorithmException {
    CMSTypedData cmsData = new CMSProcessableByteArray(data);
    CMSSignedData signedData = signData(cmsData);
    return signedData.getEncoded();

  }

  public byte[] sign(P7InputStream data) throws IOException, CMSException, TSPException, NoSuchAlgorithmException {
    CMSSignedData signedData = signData(data);
    return signedData.getEncoded();
  }

  public P7Signer(final KeyStore store, TsaClient client) {
    this.store = store;
    tsaClient = client;
  }

  public P7Signer(final KeyStore store, boolean detached, TsaClient client) {
    this.detached = detached;
    tsaClient = client;
  }


}
