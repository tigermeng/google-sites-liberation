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

package com.google.sites.liberation.export;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.GoogleUtils;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.gdata.client.sites.SitesService;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.sites.liberation.util.StdOutProgressListener;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFile;

import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Processes command line arguments for exporting a site and then
 * calls SiteExporter accordingly.
 * 
 * @author bsimon@google.com (Benjamin Simon)
 */
public class Main {

  private static final Logger LOGGER = Logger.getLogger(
      Main.class.getCanonicalName());
  
  @Option(name="-proxy", usage="proxy host")
  private String proxy = null;
  
  @Option(name="-port", usage="proxt port")
  private String port = null;

  @Option(name="-user", usage="username")
  private String user = null;
  
  @Option(name="-pass", usage="password")
  private String pass = null;
  
  @Option(name="-d", usage="domain of site")
  private String domain = "google.com";
  
  @Option(name="-w", usage="webspace of site")
  private String webspace = null;
  
  @Option(name="-r", usage="export revisions as well as current content")
  private boolean exportRevisions = false;
  
  @Option(name="-h", usage="host")
  private String host = "sites.google.com";

  @Option(name="-smbJson", usage="load client secret json from a password protect samba folder")
  private String smbJson = null; // e.g. smb://cnbjmsw36/users/28851505/client_secrets.json"
  
  
	private List<String> SCOPES = Arrays.asList("https://sites.google.com/feeds");

	/** Directory to store user credentials for this application. */
	private static final java.io.File DATA_STORE_DIR = new java.io.File("./ggdownloader");

	/** Global instance of the {@link FileDataStoreFactory}. */
	private static FileDataStoreFactory DATA_STORE_FACTORY;

	/** Global instance of the JSON factory. */
	private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();

	/** Global instance of the HTTP transport. */
	private static HttpTransport HTTP_TRANSPORT;

	private void doMain(String[] args) {
		CmdLineParser parser = new CmdLineParser(this);
		Injector injector = Guice.createInjector(new SiteExporterModule());
		SiteExporter siteExporter = injector.getInstance(SiteExporter.class);
		try {
			parser.parseArgument(args);
			if (webspace == null) {
				throw new Exception("Webspace of site not specified!");
			}

			if (proxy != null && port != null) {
				System.setProperty("http.proxyHost", proxy);
				System.setProperty("https.proxyHost", proxy);
				System.setProperty("http.proxyPort", port);
				System.setProperty("https.proxyPort", port);
				if (user != null && pass != null) {
					System.setProperty("http.proxyUser", user);
					System.setProperty("http.proxyPassword", pass);
				}				
				HTTP_TRANSPORT = new NetHttpTransport.Builder().trustCertificates(GoogleUtils.getCertificateTrustStore())
						.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxy, Integer.parseInt(port)))).build();
			} else {
				HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
			}

			DATA_STORE_FACTORY = new FileDataStoreFactory(DATA_STORE_DIR);
			InputStreamReader in;
			if (smbJson != null) {
				NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("", user, pass);
				SmbFile smbFile = new SmbFile(smbJson, auth);
				in = new InputStreamReader(smbFile.getInputStream());
			} else {
				in = new InputStreamReader(new FileInputStream(new java.io.File("./client_secrets.json")));
			}
			GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, in);
			// Build flow and trigger user authorization request.
			GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(HTTP_TRANSPORT, JSON_FACTORY,
					clientSecrets, SCOPES).setDataStoreFactory(DATA_STORE_FACTORY).setAccessType("offline").build();
			Credential credential = new AuthorizationCodeInstalledApp(flow, new LocalServerReceiver()).authorize("user");
			System.out.println("Credentials saved to " + DATA_STORE_DIR.getAbsolutePath());

			SitesService sitesService = new SitesService("google-sites-liberation");
			sitesService.setOAuth2Credentials(credential);

			File directory = new File(webspace);
			siteExporter.exportSite(host, domain, webspace, exportRevisions, sitesService, directory,
					new StdOutProgressListener());
		} catch (Exception e) {
			e.printStackTrace();
			LOGGER.log(Level.SEVERE, e.getMessage());
			parser.printUsage(System.err);
			return;
		}

	}
  
  /**
   * Exports a Site.
   */
  public static void main(String[] args) {
    new Main().doMain(args);
  }
}
