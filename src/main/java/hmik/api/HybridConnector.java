package hmik.api;

import com.google.gson.*;
import okhttp3.*;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.MultipartEntity;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

import java.io.*;
import java.nio.file.Path;

import static hmik.api.SetUp.HYBRID_API_KEY;

public class HybridConnector {
    private JsonObject report;
    private String scanID;
    private String fileHash;

    private void setReport(JsonObject report) {
        this.report = report;
    }

    private void setScanID(String id){
        this.scanID=id;
    }

    private void setFileHash(String code){ this.fileHash=code;}

    public String getScanID() {
        return scanID;
    }

    public String getFileHash(){ return fileHash;}


    void scanRequest(Path path) throws IOException {

        HttpClient httpclient = new DefaultHttpClient();
        HttpPost httpPost = new HttpPost("https://www.hybrid-analysis.com/api/v2/quick-scan/file?_timestamp=1576338476477");
        httpPost.setHeader("api-key", HYBRID_API_KEY);
        FileBody uploadFilePart = new FileBody(new File(String.valueOf(path)));
        StringBody scan  = new StringBody("all");
        MultipartEntity reqEntity = new MultipartEntity();
        reqEntity.addPart("file", uploadFilePart);
        reqEntity.addPart("scan_type", scan);
        httpPost.setEntity(reqEntity);

        HttpResponse response = httpclient.execute(httpPost);
        String res = EntityUtils.toString(response.getEntity());
        httpclient.getConnectionManager().shutdown();

        JsonObject jsonResponse = new JsonParser().parse(res).getAsJsonObject();
        setScanID(jsonResponse.get("id").getAsString());
        setFileHash(jsonResponse.get("sha256").getAsString());
    }

    boolean checkReport() throws IOException {
        OkHttpClient client = new OkHttpClient();

        Request request = new Request.Builder()
                .url("https://www.hybrid-analysis.com/api/v2/quick-scan/" + getScanID())
                .addHeader("api-key", HYBRID_API_KEY)
                .build();

        Response response = client.newCall(request).execute();
        String res = response.body().string();
        response.body().close();

        if(!res.equals("")) {
            JsonObject result = new JsonParser().parse(res).getAsJsonObject();
            if(result.get("finished").getAsBoolean()){
                requestReport();
                return true;
            }
            return false;
        }
        return false;
    }

    void requestReport() throws IOException {
        OkHttpClient client = new OkHttpClient();

        Request request = new Request.Builder()
                .url("https://www.hybrid-analysis.com/api/v2/overview/" + getFileHash())
                .addHeader("api-key", HYBRID_API_KEY)
                .build();

        Response response = client.newCall(request).execute();
        String res = response.body().string();
        if( !res.equals("") && report==null) {
            JsonObject result = new JsonParser().parse(res).getAsJsonObject();
                setReport(result);
        }
    }

    void showReport(){
        if( report == null){
            System.out.println("NO report");
            return;
        }
        System.out.println("Verdict: " + report.get("verdict").getAsString());
        JsonArray scans = report.get("scanners").getAsJsonArray();
        System.out.println("Tried antivirus and result:");
        for (JsonElement scan : scans){
            System.out.println(scan.getAsJsonObject().get("name").getAsString());
        }

    }
}
