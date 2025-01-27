/************************************************************************
 *                                                                       *
 *  Signservice Support Lib                                              *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  (LGPL-3.0-or-later)                                                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.utils;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.commons.io.IOUtils;


import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper class to make is simple to start up a web server in background.
 *
 * See test class for example usage.
 *
 * @author Philip Vendil, jakobssonan
 */
public class TestHTTPServer {

    public int port;

    private Tomcat server;
    private Connector connector;
    private Context context;

    private HttpServlet handler;
    private String handlerPath;
    private String handlerPattern;
    private boolean handlerWildcard = false;

    private Map<String, String> requestBody;
    private Map<String, String> responseBody;
    private Map<String, String> mockResponseData;
    private Map<String, String> mockResponseDataMatchers;

    /**
     * Constructor for setting up a HTTP Server on a random available port
     * @throws Exception if problems occurred retrieving an available port.
     */
    public TestHTTPServer() throws Exception {
        this(ConnectionUtils.getUnusedPort());
    }

    /**
     * Constructor for setting up a HTTP Server on a specified port
     */
    public TestHTTPServer(int port) {
        this.port = port;
        requestBody = new HashMap<>();
        responseBody = new HashMap<>();
        mockResponseData = new HashMap<>();
        mockResponseDataMatchers = new HashMap<>();
    }

    /**
     * Method to add a Handler to a specific path on the web server. Should be called before
     *
     * @param handler   Instantiated servlet to handle http request/response
     * @param path      Servlet path beginning with slash
     */
    public void addHandler(HttpServlet handler, String path) {
        addHandler(handler, path, path, false);
    }

    public void addHandler(HttpServlet handler, String path, String pattern, boolean wildcard) {
        this.handler = handler;
        this.handlerPath = path;
        this.handlerPattern = pattern;
        this.handlerWildcard = wildcard;
    }

    public void setMockedResponse(String matchId, String matchValue, String mockResponse) {
        mockResponseData.put(matchId, mockResponse);
        mockResponseDataMatchers.put(matchId, matchValue);
    }

    public String getResponseBody(String matchId) {
        return responseBody.get(matchId);
    }

    public String getRequestBody(String matchId) {
        return requestBody.get(matchId);
    }

    /**
     * Method to start the web server in background.
     * @throws Exception if problems occurred starting the underlying web server.
     */
    public void start() throws Exception {
        server = new Tomcat();
        server.setBaseDir("./");

        connector = server.getConnector();
        connector.setPort(port);
        connector.setScheme("http");
        connector.setSecure(false);

        context = server.addContext("", new File(".").getAbsolutePath());

        Tomcat.addServlet(context, handlerPath, handler);
        context.addServletMappingDecoded(handlerPattern, handlerPath, handlerWildcard);

        server.start();
    }

    /**
     * Method to stop the web server run in the background.
     * @throws Exception if problems occurred stopping the underlying web server.
     */
    public void stop() throws Exception {
        server.stop();
        server.destroy();
    }

    /**
     * @return if underlying server is running.
     */
    public boolean isRunning() {
        return server.getConnector().getState().isAvailable();
    }

    public void clearResponseAndRequests() {
        responseBody.clear();
        requestBody.clear();
    }

    public HttpServlet createMockedServlet() {
        return new HttpServlet() {
            @Override
            protected void service(HttpServletRequest baseRequest, HttpServletResponse servletResponse) throws ServletException, IOException {
                String request = IOUtils.toString(baseRequest.getInputStream(), StandardCharsets.UTF_8);
                System.out.println("INCOMING REQUEST: " + request);
                String matchId = null;

                for(String id : mockResponseData.keySet()){
                    if(request.matches(mockResponseDataMatchers.get(id))){
                        matchId = id;
                        responseBody.put(matchId, mockResponseData.get(matchId));
                    }
                }
                requestBody.put(matchId, request);

                if(matchId == null){
                    servletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    requestBody.put(null, "Invalid request");
                } else {
                    servletResponse.setStatus(HttpServletResponse.SC_OK);
                }

                System.out.println("MOCKED RESPONSE: " + getResponseBody(matchId));
                servletResponse.setContentType("text/xml;charset=utf-8");
                PrintWriter out = servletResponse.getWriter();
                out.print(getResponseBody(matchId));
            }
        };
    }

}
