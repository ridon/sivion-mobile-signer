package app.sivionmobile.ridon.id.lib;

import android.content.Context;
import android.renderscript.ScriptGroup;

import com.tom_roush.pdfbox.cos.COSDictionary;
import com.tom_roush.pdfbox.cos.COSName;
import com.tom_roush.pdfbox.cos.COSString;
import com.tom_roush.pdfbox.pdmodel.PDDocument;
import com.tom_roush.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import com.tom_roush.pdfbox.util.PDFBoxResourceLoader;

import org.junit.rules.TemporaryFolder;
import org.spongycastle.cms.CMSException;
import org.spongycastle.operator.OperatorCreationException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import static android.R.id.input;

public class PdfVerifier {
  final Context context;
  public PdfVerifier (final Context context) throws IOException {
    PDFBoxResourceLoader.init(context);
    this.context = context;
  }

  public List<PdfVerification> verify(final InputStream input, final String password) throws IOException, CertificateException, CMSException, OperatorCreationException {
    List<PdfVerification> list = new ArrayList<PdfVerification>();

    final File tempFile = File.createTempFile("sivionmobilesigner", null, context.getCacheDir());

    byte[] buffer = new byte[input.available()];
    input.read(buffer);

    OutputStream outStream = new FileOutputStream(tempFile);
    outStream.write(buffer);

    PDDocument document = PDDocument.load(tempFile, password);

    for (PDSignature sig : document.getSignatureDictionaries()) {

      String subFilter = sig.getSubFilter();
      switch (subFilter) {
        case "adbe.pkcs7.detached":
          PdfVerification v = verifyDetached(sig, tempFile);
          list.add(v);
          break;
      }
    }
    document.close();
    tempFile.delete();
    return list;
  }

  PdfVerification verifyDetached(PDSignature sig, File tempFile) throws IOException, CMSException, CertificateException, OperatorCreationException  {
    COSDictionary sigDict = (COSDictionary) sig.getCOSObject();
    COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);

    FileInputStream fis = new FileInputStream(tempFile);
    byte[] buf = sig.getSignedContent(fis);
    P7Verifier verifier = new P7Verifier(contents.getBytes(), buf);

    PdfVerification v = new PdfVerification(verifier.verify(), sig.getName(), sig.getLocation(), sig.getReason(), sig.getSignDate().getTime(), verifier.signedDate());
    return v;
  }
}
