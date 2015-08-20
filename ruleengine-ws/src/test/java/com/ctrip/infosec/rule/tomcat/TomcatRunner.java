package com.ctrip.infosec.rule.tomcat;

import org.apache.catalina.startup.Tomcat;

/**
 * Created by yxjiang on 2015/6/30.
 */
public class TomcatRunner {

    public static void main(String[] args) throws Exception {
        Tomcat tomcat = new Tomcat();
        tomcat.setPort(8080);
        tomcat.setBaseDir(System.getProperty("java.io.tmpdir"));
        tomcat.addWebapp("/", System.getProperty("user.dir") + "/src/main/webapp");
//        tomcat.enableNaming();
        tomcat.getConnector().setURIEncoding("UTF-8");

        tomcat.start();
        tomcat.getServer().await();
    }
}
