package hmik.api;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.MultipartEntity;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Set;

import static hmik.api.SetUp.META_API_KEY;

public class MetaDefenderConnector {
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
        HttpPost httpPost = new HttpPost("http://api.metadefender.com/v4/file");
        httpPost.setHeader("apikey", META_API_KEY);
        httpPost.setHeader("Content-Type", "application/octet-stream");
        FileBody uploadFilePart = new FileBody(new File(String.valueOf(path)));
        MultipartEntity reqEntity = new MultipartEntity();
        reqEntity.addPart("file", uploadFilePart);
        httpPost.setEntity(reqEntity);

        HttpResponse response = httpclient.execute(httpPost);
        String res = EntityUtils.toString(response.getEntity());
        httpclient.getConnectionManager().shutdown();

        JsonObject jsonResponse = new JsonParser().parse(res).getAsJsonObject();
        System.out.println(jsonResponse.toString());
        setScanID(jsonResponse.get("data_id").getAsString());
        setFileHash(jsonResponse.get("sha256").getAsString());
    }

    boolean checkReport() throws IOException {
        OkHttpClient client = new OkHttpClient();

        Request request = new Request.Builder()
                .url("https://api.metadefender.com/v4/hash/" + getFileHash())
                .addHeader("apikey", META_API_KEY)
                .build();

        Response response = client.newCall(request).execute();
        String res = response.body().string();
        if( !res.equals("") && report==null) {
            JsonObject result = new JsonParser().parse(res).getAsJsonObject();
            setReport(result);
            if(result.get("scan_results").getAsJsonObject().get("progress_percentage").getAsInt() == 100){
                return true;
            }
        }
        return false;
    }

    void showReport(){
        if( report == null){
            System.out.println("NO report");
            return;
        }
        System.out.println(report.toString());
        System.out.println("Verdict: " + report.get("scan_results").getAsJsonObject().get("scan_all_result_a").getAsString());
        JsonObject scanners = report.get("scan_results").getAsJsonObject().get("scan_details").getAsJsonObject();
        Set<String> scans = scanners.keySet();
        System.out.println("Tried antivirus and result:");
        for (String scan : scans){
            System.out.println(scan);
        }
    }
}
