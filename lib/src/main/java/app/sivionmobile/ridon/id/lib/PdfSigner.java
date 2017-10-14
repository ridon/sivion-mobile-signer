package app.sivionmobile.ridon.id.lib;

import android.content.Context;

import com.tom_roush.pdfbox.pdmodel.PDDocument;
import com.tom_roush.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import com.tom_roush.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import com.tom_roush.pdfbox.util.PDFBoxResourceLoader;

import org.spongycastle.cms.CMSException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Calendar;


public class PdfSigner implements SignatureInterface {

  P7Signer signer = null;
  File file = null;

  PdfSigner(Context context, P7Signer signer, final File file) {
    this.signer = signer;
    this.file = file;
    PDFBoxResourceLoader.init(context);
  }

  void sign(File output, final String alias, final String name, final String location, final String reason) throws IOException {
    FileOutputStream fos = new FileOutputStream(output);
    PDDocument doc = PDDocument.load(file);
    PDSignature sig = new PDSignature();
    sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
    sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
    sig.setName(name);
    sig.setLocation(location);
    sig.setReason(reason);
    sig.setSignDate(Calendar.getInstance());
    doc.addSignature(sig, this);
    doc.saveIncremental(fos);
    doc.close();
    fos.close();

  }

  @Override
  public byte[] sign(InputStream content) throws IOException {
    P7InputStream data = new P7InputStream(content);

    try {
      return signer.sign(data);
    } catch (CMSException e) {
      e.printStackTrace();
      throw new IOException(e.getMessage());
    }
  }
}
