package hmik.api;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Set;

import static hmik.api.SetUp.VTAPIKEY;

public class VirusTotalConnector {
    private JsonObject report;
    private String scanID;

    private void setReport(JsonObject report) {
        this.report = report;
    }

    private void setScanID(String id){
        this.scanID=id;
    }


    String loadText(Path p){
        File file =  new File(String.valueOf(p));
        byte[] bytes = new byte[(int)file.length()];
        return Base64.getEncoder().encodeToString(bytes);
    }

    void scanRequest(Path p) throws IOException {
        String text = loadText(p);
        OkHttpClient client = new OkHttpClient();
        Gson gson = new Gson();
        RequestBody body = new FormBody.Builder()
                .add("apikey", VTAPIKEY)
                .add("file", "data:'';name='';base64," +
                        text
                )
                .build();

        Request request = new Request.Builder()
                .url("https://try.readme.io/https://www.virustotal.com/vtapi/v2/file/scan")
                .addHeader("Origin", "https://developers.virustotal.com")
                .post(body)
                .build();

        Response response = client.newCall(request).execute();
        JsonObject jsonResponse = new JsonParser().parse(response.body().string()).getAsJsonObject();
        setScanID(jsonResponse.get("scan_id").getAsString());
    }

    boolean checkReport() throws IOException {
        if (report == null){
            this.requestReport();
        }
        return report!=null;
    }

    void requestReport() throws IOException {
        OkHttpClient client = new OkHttpClient();

        String query = "apikey="+VTAPIKEY+"&resource="+scanID+"&allinfo=true";

        Request request = new Request.Builder()
                .url("https://try.readme.io/https://www.virustotal.com/vtapi/v2/file/report?"+query)
                .addHeader("Origin", "https://developers.virustotal.com")
                .build();

        Response response = client.newCall(request).execute();
        String res = response.body().string();
        if( res != null && !res.equals("")) {
            JsonObject result = new JsonParser().parse(res).getAsJsonObject();
            if(result.get("response_code").getAsInt() == 1){
                setReport(result);
            }
        }
    }

    void showReport(){
        if(report == null){
            System.out.println("No report available");
            return;
        }
        System.out.println("Total: " + report.get("total").getAsString() + ", positive: " + report.get("positives").getAsString());
        JsonObject scans = report.get("scans").getAsJsonObject();
        Set<String> keys = scans.keySet();
        System.out.println("Tried antivirus and result:");
        for (String k : keys){
            System.out.println(k  + ": " + scans.get(k).getAsJsonObject().get("detected").getAsString());
        }
    }
}
