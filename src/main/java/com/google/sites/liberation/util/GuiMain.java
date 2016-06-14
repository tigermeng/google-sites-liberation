/*
 * Copyright (C) 2009 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.sites.liberation.util;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JButton;
import javax.swing.JCheckBox;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.border.EmptyBorder;

import com.google.api.client.auth.oauth2.Credential;

import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.GoogleUtils;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;

import com.google.gdata.client.sites.SitesService;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.sites.liberation.export.SiteExporter;
import com.google.sites.liberation.export.SiteExporterModule;


/**
 * Provides a GUI for initiating a Sites import or export.
 * 
 * @author bsimon@google.com (Benjamin Simon)
 */
public class GuiMain {

  private static final Logger LOGGER = Logger.getLogger(GuiMain.class
      .getCanonicalName());

  private List<String> SCOPES = Arrays
      .asList("https://sites.google.com/feeds"); //TODO do i need drive scope? DriveScopes.DRIVE_METADATA_READONLY

  private Credential credential = null;

  private JFrame optionsFrame;
  private JFrame progressFrame;
  private JTextField hostField;
  private JTextField domainField;
  private JTextField webspaceField;

  private JTextField fileField;
  private JCheckBox revisionsCheckBox;
  private JTextArea textArea;
  private JProgressBar progressBar;
  private JButton doneButton;

  /** Directory to store user credentials for this application. */
  private static final java.io.File DATA_STORE_DIR = new java.io.File(
      System.getProperty("user.home"), ".google-engineer-credentials/ggdownloader"); //TODO must put in a safe folder, not 666/777

  // don't share the secret file
  private static final java.io.File SECRET_FILE = new java.io.File(
	      System.getProperty("user.home"), "client_secrets.json");

  /** Global instance of the {@link FileDataStoreFactory}. */
  private static FileDataStoreFactory DATA_STORE_FACTORY;

  /** Global instance of the JSON factory. */
  private static final JsonFactory JSON_FACTORY =
      JacksonFactory.getDefaultInstance();

  /** Global instance of the HTTP transport. */
  private static HttpTransport HTTP_TRANSPORT;

  static final String PROXY_HOST;
  static final String PROXY_PORT;
  static final String PROXY_USER;
  static final String PROXY_PASS;
  
  static {
	PROXY_HOST = System.getProperty("http.proxyHost");
	PROXY_PORT = System.getProperty("http.proxyPort");
	PROXY_USER = System.getProperty("http.proxyUser");
	PROXY_PASS = System.getProperty("http.proxyPassword");
    System.setProperty("https.proxyHost", PROXY_HOST);
    System.setProperty("https.proxyPort", PROXY_PORT);
    
      try {
          HTTP_TRANSPORT = new NetHttpTransport.Builder()
            .trustCertificates(GoogleUtils.getCertificateTrustStore())
            .setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(PROXY_HOST, Integer.parseInt(PROXY_PORT))))
            .build();
          DATA_STORE_FACTORY = new FileDataStoreFactory(DATA_STORE_DIR);
      } catch (Throwable t) {
          t.printStackTrace();
          System.exit(1);
      }
  }  
  private GuiMain() throws Exception {
    try {
      UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
    } catch (ClassNotFoundException e) {
      LOGGER.log(Level.WARNING, "Unable to set look and feel.", e);
    } catch (InstantiationException e) {
      LOGGER.log(Level.WARNING, "Unable to set look and feel.", e);
    } catch (IllegalAccessException e) {
      LOGGER.log(Level.WARNING, "Unable to set look and feel.", e);
    } catch (UnsupportedLookAndFeelException e) {
      LOGGER.log(Level.WARNING, "Unable to set look and feel.", e);
    }
    initOptionsFrame();
    initProgressFrame();
    
    startAction();
  }

  private void initOptionsFrame() throws Exception {
    optionsFrame = new JFrame("Sites Import/Export");
    JPanel mainPanel = new JPanel();
    GridLayout layout = new GridLayout(0, 2);
    mainPanel.setLayout(layout);
    mainPanel.add(new JLabel(" Host: "));
    hostField = new JTextField("sites.google.com");
    mainPanel.add(hostField);
    mainPanel.add(new JLabel(" Domain: "));
    domainField = new JTextField("google.com");
    mainPanel.add(domainField);
    mainPanel.add(new JLabel(" Webspace: "));
    webspaceField = new JTextField("gms_distribution");
    mainPanel.add(webspaceField);
    mainPanel.add(new JLabel(" Import/Export Revisions: "));
    revisionsCheckBox = new JCheckBox();
    mainPanel.add(revisionsCheckBox);
    fileField = new JTextField("/home/CORPUSERS/28851505/0testing"); //TODO


    JButton directoryButton = new JButton("Choose Target Directory");
    mainPanel.add(directoryButton);
    mainPanel.add(fileField);


    mainPanel.add(new JPanel());
    mainPanel.add(new JPanel());
    mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
    optionsFrame.getContentPane().add(mainPanel);
    optionsFrame.pack();
    optionsFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    optionsFrame.setVisible(true);
    

  }

  private void initProgressFrame() {
    progressFrame = new JFrame("Progress");
    JPanel mainPanel = new JPanel();
    mainPanel.setLayout(new BorderLayout());
    progressBar = new JProgressBar();
    progressBar.setMinimum(0);
    progressBar.setMaximum(100);
    progressBar.setPreferredSize(new Dimension(500, 25));
    JPanel progressPanel = new JPanel();
    progressPanel.add(progressBar);
    progressPanel.setBorder(new EmptyBorder(10, 0, 0, 0));
    mainPanel.add(progressPanel, BorderLayout.NORTH);
    textArea = new JTextArea();
    textArea.setRows(20);
    textArea.setEditable(false);
    JScrollPane scrollPane = new JScrollPane(textArea);
    scrollPane.setBorder(new EmptyBorder(10, 10, 10, 10));
    mainPanel.add(scrollPane, BorderLayout.CENTER);
    doneButton = new JButton("Done");
    doneButton.setPreferredSize(new Dimension(495, 25));
    doneButton.setEnabled(false);
    doneButton.addActionListener(new ActionListener() {
      @Override
      public void actionPerformed(ActionEvent e) {
        doneButton.setEnabled(false);
        progressFrame.setVisible(false);
        optionsFrame.setVisible(true);
      }
    });
    JPanel donePanel = new JPanel();
    donePanel.setLayout(new BorderLayout());
    donePanel.add(doneButton, BorderLayout.CENTER);
    donePanel.setBorder(new EmptyBorder(0, 10, 10, 10));
    mainPanel.add(donePanel, BorderLayout.SOUTH);
    progressFrame.getContentPane().add(mainPanel);
    progressFrame.pack();
    progressFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
  }


  /**
   * Creates an authorized Credential object.
   * @return an authorized Credential object.
 * @throws Exception 
   */
  private Credential getCredentials() throws Exception {
      // Load client secrets.
      InputStream in = new FileInputStream(SECRET_FILE);
      GoogleClientSecrets clientSecrets =
          GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

      // Build flow and trigger user authorization request.
      GoogleAuthorizationCodeFlow flow =
              new GoogleAuthorizationCodeFlow.Builder(
                      HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
              .setDataStoreFactory(DATA_STORE_FACTORY)
              .setAccessType("offline")
              .build();
      Credential credential = new AuthorizationCodeInstalledApp(
          flow, new LocalServerReceiver()).authorize("user");
      System.out.println(
              "Credentials saved to " + DATA_STORE_DIR.getAbsolutePath());
      return credential;
  }
  
  
  private void startAction() throws Exception {
    optionsFrame.setVisible(false);
    progressBar.setValue(0);
    progressBar.setIndeterminate(true);
    textArea.setText("");
    progressFrame.setVisible(true);
    run();
  }



  /**
   * Launches a new GuiMain, allowing a user to graphically initiate a Sites
   * import or export.
 * @throws Exception 
   */
  public static void main(String[] args) throws Exception {
    new GuiMain();
  }




    private void run() throws Exception {
      String host = hostField.getText();
      String domain = (domainField.getText().equals("")) ? null
          : domainField.getText();
      String webspace = webspaceField.getText();
      boolean revisions = revisionsCheckBox.isSelected();
      File directory = new File(fileField.getText());
      String applicationName = "sites-liberation-5";
      SitesService sitesService = new SitesService(applicationName);
      credential = getCredentials();
      sitesService.setOAuth2Credentials(credential);
      
      //String encoded = new String(Base64.encodeBase64(new String(PROXY_USER + ":" + PROXY_PASS).getBytes()));
      //String base64encodedCredentials = "Basic " + encoded;
      //sitesService.getRequestFactory().setPrivateHeader("Proxy-Authorization", base64encodedCredentials);
      
        Injector injector = Guice.createInjector(new SiteExporterModule());
        SiteExporter siteExporter = injector.getInstance(SiteExporter.class);
        siteExporter.exportSite(host, domain, webspace, revisions,
            sitesService, directory, new GuiProgressListener(progressBar, textArea));

        doneButton.setEnabled(true);
    }


}
