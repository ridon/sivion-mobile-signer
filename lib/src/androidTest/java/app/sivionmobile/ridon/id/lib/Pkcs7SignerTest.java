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
import org.spongycastle.x509.X509V3CertificateGenerator;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class Pkcs7SignerTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static String alias = "omama";
    @Test
    public void useAppContext() throws Exception {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getTargetContext();

        assertEquals("app.sivionmobile.ridon.id.lib.test", appContext.getPackageName());

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

      P7Signer signer = new P7Signer(keyStore);

      String test = "olala";
      signer.addSigner(alias);
      byte[] signed = signer.sign(test.getBytes("UTF-8"));
      assertNotEquals(signed.length, 0);
      System.err.println(Arrays.toString(signed));

    }
}
