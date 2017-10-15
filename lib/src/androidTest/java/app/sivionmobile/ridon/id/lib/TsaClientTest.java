package app.sivionmobile.ridon.id.lib;

import android.support.test.InstrumentationRegistry;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import android.support.test.runner.AndroidJUnit4;


import java.net.URL;
import java.security.MessageDigest;
import java.security.Security;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class TsaClientTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void useAppContext() throws Exception {
    URL url = new URL("https://freetsa.org/tsr");
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    TsaClient client = new TsaClient(url, null, null, digest);

    String test = "omama";
    byte[] token = client.getToken(test.getBytes("UTF-8"));
    assertNotEquals(token.length, 0);

  }
}