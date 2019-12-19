package hmik.api;

import java.nio.file.Path;
import java.nio.file.Paths;
import static java.lang.System.exit;
import static java.lang.Thread.sleep;

public class URLConnectionReader {


    public static void main(String[] args) throws Exception {

        //File file =  new File("/home/hmikulic/Pictures/Screenshot_20191111_214109.png");
        //File file =  new File("//home/hmikulic/Desktop/nbmp.txt");
        //File file =  new File("//home/hmikulic/Downloads/Životopis.pdf");
        Path p = Paths.get("//home/hmikulic/Downloads/Životopis.pdf");


        HybridConnector hConnector = new HybridConnector();
        VirusTotalConnector vtConnector = new VirusTotalConnector();

        hConnector.scanRequest(p);
        vtConnector.scanRequest(p);

        boolean VTReportReady = false;
        boolean hReportrReady = false;
        int i = 0;
        while(!VTReportReady || !hReportrReady){
            sleep(1000);
            VTReportReady = vtConnector.checkReport();
            hReportrReady = hConnector.checkReport();
            System.out.println("VT Report ready " + VTReportReady + ", hreport ready " + hReportrReady);
            System.out.println("Pokušaj " + i++);
        }
        vtConnector.showReport();
        System.out.println("--------------------------------------------------------------------------");
        hConnector.showReport();

        exit(0);
    }
}