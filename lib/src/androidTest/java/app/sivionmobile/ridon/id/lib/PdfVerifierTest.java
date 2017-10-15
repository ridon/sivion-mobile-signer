package app.sivionmobile.ridon.id.lib;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import static org.junit.Assert.*;


@RunWith(AndroidJUnit4.class)
public class PdfVerifierTest {

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();
  private static String alias = "omama";

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

  @Test
  public void useAppContext() throws Exception {

    Context appContext = InstrumentationRegistry.getTargetContext();
    File temp = folder.newFile("omama.pdf");
    File tempOutput = folder.newFile("omama.signed.pdf");
    InputStream is = appContext.getResources().getAssets().open("omama.pdf");
    byte[] buffer = new byte[is.available()];
    is.read(buffer);

    OutputStream os = new FileOutputStream(temp);
    os.write(buffer);
    os.close();

    KeyStore keyStore = getKeyStore(appContext);

    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    TsaClient c = new TsaClient(new URL("https://freetsa.org/tsr"), null, null, digest);
    P7Signer signer = new P7Signer(keyStore, c);
    signer.addSigner(alias);

    PdfSigner pdfSigner = new PdfSigner(appContext, signer, temp);
    pdfSigner.sign(tempOutput, alias, "Name", "Location", "Reason");

    File signedFile = new File(tempOutput.getAbsolutePath());
    assertEquals(signedFile.exists(), true);

    PdfVerifier verifier = new PdfVerifier(appContext, signedFile, "");
    List<PdfVerification> res = verifier.verify();
    assertEquals(res.size(), 1);

    Date now = new Date();
    PdfVerification r1 = res.get(0);
    assertEquals(r1.name(), "Name");
    assertEquals(r1.location(), "Location");
    assertEquals(r1.reason(), "Reason");
    assertNotEquals(now.before(r1.date()), true);

    List<SignatureVerification> sigs = r1.signatures();
    assertEquals(sigs.size(), 1);
    SignatureVerification sig = sigs.get(0);

    assertEquals(sig.isVerified(), true);
    assertEquals(sig.isTrusted(), false);

  }
}
