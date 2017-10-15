package app.sivionmobile.ridon.id.lib;

import com.tom_roush.pdfbox.io.IOUtils;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.crypto.Digest;
import org.spongycastle.tsp.TSPException;
import org.spongycastle.tsp.TimeStampRequest;
import org.spongycastle.tsp.TimeStampRequestGenerator;
import org.spongycastle.tsp.TimeStampResponse;
import org.spongycastle.tsp.TimeStampToken;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

public class TsaClient {
  final URL url;
  final String username;
  final String password;
  final MessageDigest digest;

  public TsaClient(final URL url, final String username, final String password, final MessageDigest digest) {
    this.url = url;
    this.username = username;
    this.password = password;
    this.digest = digest;
  }

  private ASN1ObjectIdentifier getOid() throws NoSuchAlgorithmException {
    String algo = digest.getAlgorithm();
    if (algo.equals("SHA-256")) {
      return new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha256.getId());
    }
    throw new NoSuchAlgorithmException("This algorithm is not available: " + algo);
  }

  private byte[] getResponse(byte[] req) throws IOException {
    URLConnection connection = url.openConnection();
    connection.setDoOutput(true);
    connection.setDoInput(true);
    connection.setRequestProperty("Content-Type", "application/timestamp-query");
    if (username != null && password != null && !username.isEmpty() && !password.isEmpty()) {
      connection.setRequestProperty(username, password);
    }
    OutputStream out = connection.getOutputStream();
    out.write(req);
    IOUtils.closeQuietly(out);

    InputStream input = connection.getInputStream();
    byte[] ret = IOUtils.toByteArray(input);
    IOUtils.closeQuietly(input);

    return ret;
  }

  public byte[] getToken(byte[] data) throws IOException, TSPException, NoSuchAlgorithmException {
    digest.reset();
    byte[] hash = digest.digest(data);

    SecureRandom r = new SecureRandom();
    int nonce = r.nextInt();

    TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
    gen.setCertReq(true);
    ASN1ObjectIdentifier digestId = getOid();
    TimeStampRequest req = gen.generate(digestId, hash, BigInteger.valueOf(nonce));

    byte[] res = getResponse(req.getEncoded());
    TimeStampResponse tsResponse = new TimeStampResponse(res);
    tsResponse.validate(req);

    TimeStampToken token = tsResponse.getTimeStampToken();
    if (token == null) {
      throw new IOException("No token from TSA");
    }
    return token.getEncoded();

  }

}