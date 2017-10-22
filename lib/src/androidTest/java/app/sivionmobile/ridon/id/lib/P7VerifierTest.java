package app.sivionmobile.ridon.id.lib;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.spongycastle.jce.X509Principal;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.Hex;
import org.spongycastle.x509.X509V3CertificateGenerator;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class P7VerifierTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static KeyStore getKeyStore(Context appContext) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException, IOException, CertificateException {

    Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
    Date endDate = new Date(System.currentTimeMillis() + 1 * 365 * 24 * 60 * 60 * 1000);

    Calendar notBefore = Calendar.getInstance();
    Calendar notAfter = Calendar.getInstance();
    notAfter.add(1, Calendar.YEAR);
    KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(appContext)
        .setAlias("key1")
        .setSubject(
            new X500Principal(String.format("CN=%s, OU=%s", alias,
                appContext.getPackageName())))
        .setSerialNumber(BigInteger.ONE).setStartDate(notBefore.getTime())
        .setEndDate(notAfter.getTime()).build();

    KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
    kpGenerator.initialize(spec);
    KeyPair pair = kpGenerator.generateKeyPair();

    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);

    return keyStore;
  }

  private static String alias = "omama";
  @Test
  public void DetachedTest() throws Exception {
    Context appContext = InstrumentationRegistry.getContext();


    KeyStore keyStore = getKeyStore(appContext);
    P7Signer signer = new P7Signer(keyStore, null);

    String test = "olala";
    signer.addSigner(alias);
    byte[] signed = signer.sign(test.getBytes("UTF-8"));
    assertNotEquals(signed.length, 0);

    InputStream stream = new ByteArrayInputStream(test.getBytes("UTF-8"));
    P7InputStream p7InputStream = new P7InputStream(stream);
    byte[] signedData = signer.sign(p7InputStream);
    assertNotEquals(signedData.length, 0);

    InputStream dataStream = new ByteArrayInputStream(test.getBytes("UTF-8"));
    P7Verifier verifier = new P7Verifier(signedData, dataStream);
    List<SignatureVerification> res = verifier.verify();
    assertNull(verifier.signedData);
    Iterator it = res.iterator();
    boolean gotSignatures = false;
    while (it.hasNext()) {
      SignatureVerification v = (SignatureVerification) it.next();
      assertEquals(v.isVerified(), true);
      assertEquals(v.isTrusted(), false);
      gotSignatures = true;
    }
    assertEquals(res.size(), 1);
    assertEquals(gotSignatures, true);

  }

  @Test
  public void DetachedTestWithTsa() throws Exception {
    Context appContext = InstrumentationRegistry.getContext();


    KeyStore keyStore = getKeyStore(appContext);
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    TsaClient c = new TsaClient(new URL("https://freetsa.org/tsr"), null, null, digest);
    P7Signer signer = new P7Signer(keyStore, c);

    String test = "olala";
    signer.addSigner(alias);
    byte[] signed = signer.sign(test.getBytes("UTF-8"));
    assertNotEquals(signed.length, 0);

    InputStream stream = new ByteArrayInputStream(test.getBytes("UTF-8"));
    P7InputStream p7InputStream = new P7InputStream(stream);
    byte[] signedData = signer.sign(p7InputStream);
    assertNotEquals(signedData.length, 0);

    InputStream dataStream = new ByteArrayInputStream(test.getBytes("UTF-8"));
    P7Verifier verifier = new P7Verifier(signedData, dataStream);
    List<SignatureVerification> res = verifier.verify();
    assertNotNull(verifier.signedData);
    Iterator it = res.iterator();
    boolean gotSignatures = false;
    while (it.hasNext()) {
      SignatureVerification v = (SignatureVerification) it.next();
      assertEquals(v.isVerified(), true);
      assertEquals(v.isTrusted(), false);
      gotSignatures = true;
    }
    assertEquals(res.size(), 1);
    assertEquals(gotSignatures, true);

    FileOutputStream fos = new FileOutputStream("/data/data/app.sivionmobile.ridon.id.lib.test/cache/a");
    fos.write(signedData);
    fos.close();
  }


  @Test
  public void AttachedTest() throws Exception {
    Context appContext = InstrumentationRegistry.getContext();


    KeyStore keyStore = getKeyStore(appContext);
    P7Signer signer = new P7Signer(keyStore, false, null);

    String test = "olala";
    signer.addSigner(alias);
    byte[] signed = signer.sign(test.getBytes("UTF-8"));
    assertNotEquals(signed.length, 0);

    InputStream stream = new ByteArrayInputStream(test.getBytes("UTF-8"));
    P7InputStream p7InputStream = new P7InputStream(stream);
    byte[] signedData = signer.sign(p7InputStream);
    assertNotEquals(signedData.length, 0);

    P7Verifier verifier = new P7Verifier(signedData);
    List<SignatureVerification> res = verifier.verify();
    Iterator it = res.iterator();
    boolean gotSignatures = false;
    while (it.hasNext()) {
      SignatureVerification v = (SignatureVerification) it.next();
      assertEquals(v.isVerified(), true);
      assertEquals(v.isTrusted(), false);
      gotSignatures = true;
    }
    assertEquals(res.size(), 1);
    assertEquals(gotSignatures, true);

  }


}
