package com.luay89.pharmacylabels;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.print.PrintAttributes;
import android.print.PrintDocumentAdapter;
import android.print.PrintJob;
import android.print.PrintManager;
import android.util.Base64;
import android.view.ViewGroup;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import java.io.IOException;
import java.io.OutputStream;

public final class MainActivity extends Activity {
    private static final int FILE_CHOOSER_REQUEST = 1001;
    private static final int SAVE_XLSX_REQUEST = 1002;
    private static final String XLSX_MIME =
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

    private WebView webView;
    private ValueCallback<Uri[]> filePathCallback;
    private byte[] pendingXlsx;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        webView = new WebView(this);
        webView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        setContentView(webView);

        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setDomStorageEnabled(true);
        webView.getSettings().setAllowFileAccess(true);
        webView.getSettings().setAllowContentAccess(true);
        webView.addJavascriptInterface(new AndroidBridge(), "AndroidBridge");
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(
                    WebView view, android.webkit.WebResourceRequest request) {
                return !request.getUrl().toString().startsWith("file:///android_asset/");
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                if (url.startsWith("file:///android_asset/")) {
                    view.evaluateJavascript(
                            "(function(){window.print=function(){AndroidBridge.printLabels();};})();",
                            null);
                }
            }
        });
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(
                    WebView view,
                    ValueCallback<Uri[]> callback,
                    FileChooserParams params) {
                if (filePathCallback != null) {
                    filePathCallback.onReceiveValue(null);
                }
                filePathCallback = callback;
                try {
                    startActivityForResult(params.createIntent(), FILE_CHOOSER_REQUEST);
                    return true;
                } catch (ActivityNotFoundException exception) {
                    filePathCallback = null;
                    Toast.makeText(MainActivity.this,
                            "تعذر فتح مدير الملفات", Toast.LENGTH_LONG).show();
                    return false;
                }
            }
        });
        webView.loadUrl("file:///android_asset/index.html");
    }

    private final class AndroidBridge {
        @JavascriptInterface
        public void printLabels() {
            runOnUiThread(MainActivity.this::printLabels);
        }

        @JavascriptInterface
        public void saveXlsx(String filename, String base64) {
            final byte[] content;
            try {
                content = Base64.decode(base64, Base64.DEFAULT);
            } catch (IllegalArgumentException exception) {
                runOnUiThread(() -> Toast.makeText(MainActivity.this,
                        "تعذر تجهيز ملف Excel", Toast.LENGTH_LONG).show());
                return;
            }
            runOnUiThread(() -> requestSaveXlsx(filename, content));
        }
    }

    private void printLabels() {
        PrintManager printManager = (PrintManager) getSystemService(PRINT_SERVICE);
        if (printManager == null) {
            Toast.makeText(this, "خدمة الطباعة غير متاحة على هذا الجهاز",
                    Toast.LENGTH_LONG).show();
            return;
        }
        PrintDocumentAdapter adapter = webView.createPrintDocumentAdapter("ملصقات المنتجات");
        PrintAttributes attributes = new PrintAttributes.Builder()
                .setMediaSize(PrintAttributes.MediaSize.UNKNOWN_PORTRAIT)
                .setMinMargins(new PrintAttributes.Margins(0, 0, 0, 0))
                .build();
        PrintJob job = printManager.print("ملصقات المنتجات", adapter, attributes);
        if (job == null) {
            Toast.makeText(this, "تعذر بدء مهمة الطباعة", Toast.LENGTH_LONG).show();
        }
    }

    private void requestSaveXlsx(String filename, byte[] content) {
        pendingXlsx = content;
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType(XLSX_MIME);
        intent.putExtra(Intent.EXTRA_TITLE, safeFilename(filename));
        try {
            startActivityForResult(intent, SAVE_XLSX_REQUEST);
        } catch (ActivityNotFoundException exception) {
            pendingXlsx = null;
            Toast.makeText(this, "تعذر فتح نافذة حفظ الملف", Toast.LENGTH_LONG).show();
        }
    }

    private String safeFilename(String filename) {
        if (filename == null || filename.trim().isEmpty()) {
            return "قائمة-المنتجات.xlsx";
        }
        return filename.replaceAll("[\\\\/:*?\"<>|]", "_");
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == FILE_CHOOSER_REQUEST) {
            if (filePathCallback != null) {
                Uri[] result = resultCode == RESULT_OK
                        ? WebChromeClient.FileChooserParams.parseResult(resultCode, data)
                        : null;
                filePathCallback.onReceiveValue(result);
                filePathCallback = null;
            }
            return;
        }
        if (requestCode == SAVE_XLSX_REQUEST) {
            byte[] content = pendingXlsx;
            pendingXlsx = null;
            if (resultCode != RESULT_OK || data == null || data.getData() == null
                    || content == null) {
                return;
            }
            try (OutputStream output = getContentResolver().openOutputStream(data.getData())) {
                if (output == null) {
                    throw new IllegalStateException("Unable to open destination");
                }
                output.write(content);
                Toast.makeText(this, "تم حفظ ملف Excel", Toast.LENGTH_LONG).show();
            } catch (IOException | IllegalStateException exception) {
                Toast.makeText(this, "تعذر حفظ ملف Excel", Toast.LENGTH_LONG).show();
            }
        }
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        if (filePathCallback != null) {
            filePathCallback.onReceiveValue(null);
            filePathCallback = null;
        }
        if (webView != null) {
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }
}
