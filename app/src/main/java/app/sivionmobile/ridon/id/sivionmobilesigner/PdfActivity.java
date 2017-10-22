package app.sivionmobile.ridon.id.sivionmobilesigner;

import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.pdf.PdfRenderer;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.spongycastle.cms.CMSException;
import org.spongycastle.operator.OperatorCreationException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.List;

import app.sivionmobile.ridon.id.lib.PdfVerification;
import app.sivionmobile.ridon.id.lib.PdfVerifier;
import app.sivionmobile.ridon.id.lib.SignatureVerification;

import static android.provider.AlarmClock.EXTRA_MESSAGE;
import static app.sivionmobile.ridon.id.sivionmobilesigner.R.id.parent;

public class PdfActivity extends AppCompatActivity {

  boolean infoShown = false;
  Uri filePath;
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_pdf);
    Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
    setSupportActionBar(toolbar);

    Intent intent = getIntent();

    filePath = Uri.parse(intent.getStringExtra(LoungeActivity.PDF_OPEN));

    FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
    fab.setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View view) {
        verifyPdf(view);
      }
    });
    getSupportActionBar().setDisplayHomeAsUpEnabled(true);
  }

  @Override
  protected void onStart()
  {
    super.onStart();

    try {
      loadPdf();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  void verifyPdf(View view) {
    final InputStream signedFile;
    boolean success = false;
    try {
      signedFile = getApplicationContext().getContentResolver().openInputStream(filePath);

      PdfVerifier verifier = new PdfVerifier(getApplicationContext());
      List<PdfVerification> res = verifier.verify(signedFile, "");

      populateInfo(res);
      if (res != null && !res.isEmpty()){
        success = true;
      }
    } catch (CertificateException | OperatorCreationException | IOException | CMSException e) {
      e.printStackTrace();
    }

    if (success == false) {
      Snackbar.make(view, "This document does not have any digital signatures", Snackbar.LENGTH_LONG)
          .setAction("Action", null).show();
    } else {
      infoShown = !infoShown;
      toggleInfo(infoShown);
    }

  }

  void setField(View view, int id, String value) {
    TextView t = (TextView) view.findViewById(id);
    t.setText(value);
  }
  void populateInfo(List<PdfVerification> res) {

    LinearLayout l = (LinearLayout) findViewById(R.id.signatures);
    for (PdfVerification f : res) {
      View view = LayoutInflater.from(getApplicationContext()).inflate(R.layout.pdf_signatures, null);

      setField(view, R.id.tvSigner, f.name());
      setField(view, R.id.tvLocation, f.location());
      setField(view, R.id.tvReason, f.reason());

      setField(view, R.id.tvSigningDate, f.date().toLocaleString());

      if (f.signedDate() != null) {
        setField(view, R.id.tvTimestamp, f.signedDate().toLocaleString());
      } else {
        setField(view, R.id.tvTimestamp, "No timestamp available");
      }

      View certView = LayoutInflater.from(getApplicationContext()).inflate(R.layout.certificates, null);
      LinearLayout certPlaceholder = (LinearLayout) view.findViewById(R.id.certificates);
      for (SignatureVerification s : f.signatures()) {
        setField(certView, R.id.tvCertSerial, s.serialNumber());
        setField(certView, R.id.tvCertValidity, s.validity());
        setField(certView, R.id.tvCertSubject, s.subject());
        setField(certView, R.id.tvCertIssuer, s.issuer());
        setField(certView, R.id.tvCertPublicKey, s.publicKey());
        setField(certView, R.id.tvCertAlgorithm, s.algorithm());
        setField(certView, R.id.tvCertFingerprint, s.fingerprint());

        certPlaceholder.addView(certView);
      }
      l.addView(view);
    }
  }
  void toggleInfo(boolean showInfo) {
    ImageView imageView = (ImageView) findViewById(R.id.pdfBitmap);
    ScrollView infoView = (ScrollView) findViewById(R.id.contentWrapper);
    if (showInfo == false) {
      imageView.setVisibility(View.VISIBLE);
      infoView.setVisibility(View.INVISIBLE);
      ViewGroup.LayoutParams p = imageView.getLayoutParams();
      p.width = ViewGroup.LayoutParams.MATCH_PARENT;
      p.height = ViewGroup.LayoutParams.MATCH_PARENT;
      imageView.setLayoutParams(p);
    } else {
      imageView.setVisibility(View.INVISIBLE);
      infoView.setVisibility(View.VISIBLE);
      ViewGroup.LayoutParams p = infoView.getLayoutParams();
      p.width = ViewGroup.LayoutParams.MATCH_PARENT;
      p.height = ViewGroup.LayoutParams.MATCH_PARENT;
      infoView.setLayoutParams(p);
    }
  }

  void loadPdf() throws IOException {
    if (filePath.toString().isEmpty()) return;

    final ParcelFileDescriptor fd = getApplicationContext().getContentResolver().openFileDescriptor(filePath, "r");
    PdfRenderer renderer = new PdfRenderer(fd);

    final int pageCount = renderer.getPageCount();
    PdfRenderer.Page page = renderer.openPage(0);

    ImageView imageView = (ImageView) findViewById(R.id.pdfBitmap);
    Bitmap bitmap = Bitmap.createBitmap(page.getWidth(), page.getHeight(),
        Bitmap.Config.ARGB_8888);
    page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY);
    imageView.setImageBitmap(bitmap);
    page.close();
    renderer.close();
  }
}
