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
        Path p = Paths.get("//home/hmikulic/Desktop/eicar.com");


        HybridConnector hConnector = new HybridConnector();
        VirusTotalConnector vtConnector = new VirusTotalConnector();
        MetaDefenderConnector mdConnector = new MetaDefenderConnector();

        mdConnector.scanRequest(p);
        hConnector.scanRequest(p);
        vtConnector.scanRequest(p);

        boolean VTReportReady = false;
        boolean hReportrReady = false;
        boolean mdReportReady = false;
        int i = 0;
        while(!VTReportReady || !hReportrReady || !mdReportReady){
            sleep(1000);
            if(VTReportReady == false)
                VTReportReady = vtConnector.checkReport();
            if(hReportrReady == false)
                hReportrReady= hConnector.checkReport();
            if(mdReportReady == false)
                mdReportReady= mdConnector.checkReport();
            System.out.println("VT Report ready " + VTReportReady + ", hreport ready " + hReportrReady + ", MDreport ready " + mdReportReady);
            System.out.println("Pokušaj " + i++);
        }
        vtConnector.showReport();
        System.out.println("--------------------------------------------------------------------------");
        hConnector.showReport();
        System.out.println("--------------------------------------------------------------------------");
        mdConnector.showReport();

        exit(0);
    }
}