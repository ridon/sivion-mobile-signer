package app.sivionmobile.ridon.id.lib;

import android.content.Context;

import com.tom_roush.pdfbox.cos.COSDictionary;
import com.tom_roush.pdfbox.cos.COSName;
import com.tom_roush.pdfbox.cos.COSString;
import com.tom_roush.pdfbox.pdmodel.PDDocument;
import com.tom_roush.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import com.tom_roush.pdfbox.util.PDFBoxResourceLoader;

import org.spongycastle.cms.CMSException;
import org.spongycastle.operator.OperatorCreationException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

public class PdfVerifier {
  final File file;
  final String password;

  public PdfVerifier (final Context context, final File file, final String password) {
    this.file = file;
    this.password = password;
    PDFBoxResourceLoader.init(context);
  }

  List<PdfVerification> verify() throws IOException, CertificateException, CMSException, OperatorCreationException {
    List<PdfVerification> list = new ArrayList<PdfVerification>();

    PDDocument document = PDDocument.load(file, password);

    for (PDSignature sig : document.getSignatureDictionaries()) {

      String subFilter = sig.getSubFilter();
      switch (subFilter) {
        case "adbe.pkcs7.detached":
          PdfVerification v = verifyDetached(sig);
          list.add(v);
          break;
      }
    }
    return list;
  }

  PdfVerification verifyDetached(PDSignature sig) throws IOException, CMSException, CertificateException, OperatorCreationException  {
    COSDictionary sigDict = (COSDictionary) sig.getCOSObject();
    COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);

    FileInputStream fis = new FileInputStream(file);
    byte[] buf = sig.getSignedContent(fis);
    P7Verifier verifier = new P7Verifier(contents.getBytes(), buf);
    PdfVerification v = new PdfVerification(verifier.verify(), sig.getName(), sig.getLocation(), sig.getReason(), sig.getSignDate().getTime());
    return v;
  }
}
