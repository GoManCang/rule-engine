package com.ctrip.infosec.rule;

import com.ctrip.infosec.sars.util.test.JettyFactory;
import org.eclipse.jetty.server.Server;

public class Jetty {

    public static void main(String[] args) throws Exception {
        Server server = JettyFactory.buildServer(8082, "");
        server.start();
    }
}
