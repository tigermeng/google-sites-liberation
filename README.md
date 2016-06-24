# Google Sites Export Tool (Script variant)

This is an export tool for [Google Sites](http://sites.google.com/).  Using [HTML Microformats](http://microformats.org/) it generates an XHTML version of Sites content suitable for offline browsing and simple HTTP hosting

key feature inherited from fork, see fork from:
support OAuth 2.0, which is not supported by official google site API anymore

newly added features:
cmdline run only
stored credential support for oauth, replaced expireable one time access token from forked project 
support password protected proxy

Download the latest [release](https://github.com/tigermeng/google-sites-liberation/releases) and execute it now!

## User's Guide

The Sites Liberation export tool uses the Sites GData API to allow users to export an entire Google Site as static html pages to a directory on their hard drive. The html is embedded with meta-data based on the hAtom microformats specification, to allow the re-import of html back into Google Sites. Applications of the tool include backing up a Google Site, switching to or from a different service, and editing a Site offline.

### Simple Execution


You can run it in command line.
```bash
java -jar my-sites-liberation-1.0.0-jar-with-dependencies.jar -w the-site-to-export
```

on the first run, browser will be launched, to let google user login (if not yet) and grant permission to this app to manipulate user's google sites. Allow the request, credential will be stored locally. 

on the rest run, no browser or human interaction is needed anymore. the app will use StoredCredential to dump site.

### Advanced Execution

The tool is written in Java and the source code is currently hosted at code.google.com. Upon building the tool, there are three main classes. The class com.google.sites.liberation.export.Main allows the execution of a Sites export from the command line. The class com.google.sites.liberation.imprt.Main is the equivalent for a Sites import (note that the package name is "imprt," due to the Java keyword collision). The class com.google.sites.liberation.util.GuiMain provides a graphical user interface for launching both imports and exports. In all cases, the import/export takes the following arguments:

| Name | Flag | Usage |
|:-----|:-----|:------|
| Host | `-h` | If not sites.google.com, specifies the Site's host (optional).  Used for debugging. |
| Domian | `-d` | If the site is a Google Apps site, specifies the domain, e.g. dataliberation.org (optional). |
| Webspace | `-w` | Specifies the webspace of the Site, e.g. "dataliberation" for a site located at `http://sites.google.com/a/domain/dataliberation` |
| Proxy | `-proxy` | Specifies the http proxy address used to access internet. |
| Proxy Username | `-user` | Specifies the proxy user name used to access internet. |
| Proxy Password | `-pass` | Specifies the proxy password used to access internet. |
| smbJson | `-smbJson` | Load the client secret from smb://abc/xyz/client_secret.json |
| Revisions | `-r` | If this flag is included, then the revisions of all of the pages in the Site will be exported as well as the current page (optional). |

### Structure

The folder structure of an exported site is meant to mimic the Sites UI as closely as possible. Thus if exporting to a directory "rootdirectory," a top-level page normally located at webspace/pagename, would be in a file named index.html, located in rootdirectory/pagename. A subpage of that page, normally located at webspace/pagename/subpage, would be in a file named index.html in rootdirectory/pagename/subpage. Attachments are downloaded to the same directory as the index.html page to which they belong, and if revisions are exported, they will be located in a directory called "_revisions" within the directory containing the index.html file. Each revision will be in its own file named [number](revision.md).html. Additionally, if revisions are exported, a file named "history.html" will be placed in the same directory as the index.html file, containing links to all of the revisions of the page. However, the history.html file is not used for import, and thus may be omitted even when importing revisions._

### Format

The exported html uses meta-data to include semantic information necessary for import. When possible, the format follows the hAtom microformats specification. However, since the hAtom specification is meant to encode a subset of the Atom syndication format, and GData is a superset of the Atom format, there are a number of differences/additions. The following is a list of Sites API elements and their html encodings. For more information of the meaning of each element, see the Sites API documentation.

| GData Element | Microformat Class | Details |
|:--------------|:------------------|:--------|
| entry         | hentry            | As in the hAtom spec, entries are encoded by specifying the class of an html element to be "hentry." However, since all entries in the Sites API have exactly one kind (encoded as a category), the class must also contain the label for the entry's kind (e.g. "hentry webpage"). Additionally, an entry's id is encoded as the value of the id attribute in the hentry element. |
| author        | author            | As in the hAtom spec, the author of an entry is specified with the class "author". The author html element must contain an hCard, specified by the class "vcard." However, since all entries in a Site contain exactly one author with an email address, name, and nothing more, the entry should contain only one element with class "author," and the vcard can be encoded as "<a href='mailto:[email]'><a href='name.md'>name</a></a>," since this is the natural representation.|
| content       | entry-content     | As in the hAtom spec, the content of an entry is specified with an html element with class "entry-content." In the case of xhtml content, everything within the content element is taken as the content of the entry. However, since attachments contain out-of-line content, if the entry-content element contains an href attribute, then that value is taken as out-of-line content, and the element's inner-html is not parsed as content. |
| summary       | entry-summary     | As in the hAtom spec, the summary of an entry is specified with the class "entry-summary," with the element's inner html taken as the value. The summary element is used for the description of an attachment in a file cabinet. |
| title         | entry-title       | As in the hAtom spec, the title of an entry is specified with an html element with class, "entry-title." Since the title of a Sites entry can only contain plaintext, the title parsed from an "entry-title" is any plaintext within the element. |
| updated       | updated           | As in the hAom spec, the updated time of entry is specified with class, "updated", and encoded using the datetime-design-pattern. |
| sites:revision | sites:revision    | The revision number of an entry is encoded with the class, "sites:revision", where the plaintext within the inner html is parsed as an integer. |
| gs:data       | gs:data           | List pages in the GData feeds contain a gs:data element which contains gs:column elements encoding the list's column headers. Likewise the html list page entry must contain an element with class "gs:data" which itself contains encoded gs:column's. |
| gs:column     | gs:column         | The columns for a list page are encoded with class "gs:column" and must be embedded within an html element with class "gs:data." The gs:column index attribute is  encoded as the title attribute in the html element, and the name attribute is encoded as the inner html. |
| gs:field      | gs:field          | List items in the GData feeds contain gs:field elements representing each of the list item's field's indices, names, and values. The field is encoded in html as an element with class, "gs:field", where the value is the element's inner html, and the index is the element's title attribute value. The name is not encoded in the html since it can be inferred from the index and the corresponding list page to which the list item belongs. |

The parent link and pageName elements in the GData feeds are not embedded in the html, but are instead represented by the structure of the exported Site. Since each index.html file represents a page in a Site, exactly one entry with a page kind (announcementspage, announcements, filecabinet, listpage, webpage) should appear in the file. Any child entries of non-page kind (attachment, comment, listitem, webattachment) should appear in the same file and may be embedded within the page entry, but need not be. The parent link for subpages is represented by the folder structure as described in the earlier section. Finally, the pageName element is represented by the name of the directory in which the index.html file exists.

### Known Issues/Limitations
  * According to the hAtom spec, any time an "abbr" element is used, its title attribute should be parsed where inner html would normally be used. However, this is only implemented for the updated element in terms of the datetime-design-pattern.
  * The id attribute is used to store entry id's. However, these id's are URL's and this may not constitute valid html.

## Development

  The latest, most stable version of the code will always be located in the `master` branch.  See the revision history for information about the code in any other branch.

  Note:  This project is built using Maven (http://maven.apache.org/).
  
### REQUIREMENTS
  This project is built using Java 1.5 or later.  All other dependencies are managed by Maven.

#### Preparation with Ubuntu 14.04
```
sudo apt-get install -y openjdk-7-jdk maven2
```

### COMPILE
  To compile this project, execute `mvn compile`.

### TEST
  To run the tests, execute `LANG=en_us mvn test -Djava.util.logging.config.file=SEVERE`.

### JAR
  To package this project into a jar, execute `LANG=en_us mvn package`.  The jar will be located in the
  `target` directory.

### EXECUTABLE JAR
  To create a double-clickable, executable jar, execute `LANG=en_us mvn assembly:assembly`.  The jar will be
  located in the `target` directory with a `-jar-with-dependencies.jar` suffix.

### Reference
* [Google Developers Console](https://console.developers.google.com/project)
* [OAuth2 example](http://stackoverflow.com/questions/10242751/oauth-invalid-token-request-token-used-when-not-allowed)
* [OAuth2 guide](https://support.google.com/cloud/answer/6158849)
* [Google Sites API](https://developers.google.com/google-apps/sites/docs/developers_guide)
* [Google Data APIs Client Library](https://developers.google.com/gdata/javadoc/)
  * [Code in Github](https://github.com/google/gdata-java-client)
  * [Entry  Class Hierarchy](https://developers.google.com/gdata/javadoc/com/google/gdata/data/sites/package-tree)
