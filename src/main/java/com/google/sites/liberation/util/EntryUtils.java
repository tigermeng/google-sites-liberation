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

import com.google.gdata.data.ILink;
import com.google.gdata.data.Link;
import com.google.gdata.data.TextConstruct;
import com.google.gdata.data.XhtmlTextConstruct;
import com.google.gdata.data.sites.BaseContentEntry;
import com.google.gdata.data.sites.SitesLink;
import com.google.gdata.util.XmlBlob;

import java.util.Comparator;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provides utility methods for dealing with BaseContentEntry's.
 * 
 * @author bsimon@google.com (Benjamin Simon)
 */
public class EntryUtils {

  private static final Logger LOGGER = Logger.getLogger(
      EntryUtils.class.getCanonicalName());  
  
  /**
   * Returns the id given by the given entry's parent link, or null if it has
   * no parent link.
   */
  public static String getParentId(BaseContentEntry<?> entry) {
    Link link = entry.getLink(SitesLink.Rel.PARENT, ILink.Type.ATOM);
    if (link == null) {
      return null;
    }
    return link.getHref();
  }
  
  /**
   * Sets the parent link of the given entry to the given id
   */
  public static void setParentId(BaseContentEntry<?> entry, String id) {
    entry.addLink(SitesLink.Rel.PARENT, ILink.Type.ATOM, id);
  }
  
  /**
   * Returns the given entry's content as a String.
   */
  public static String getContent(BaseContentEntry<?> entry) {
    try {
      String content = ((XhtmlTextConstruct)(entry.getTextContent()
          .getContent())).getXhtml().getBlob();
      //This is due to a bug in the GData client: http://b/issue?id=2044419
      while (content.contains("]]>")) {
        content = content.replace("]]>", "]]&gt;");
      }
      return content;
    } catch(IllegalStateException e) {
      LOGGER.log(Level.WARNING, "Invalid Content", e);
      return "";
    } catch(ClassCastException e) {
      LOGGER.log(Level.WARNING, "Invalid Content", e);
      return "";
    } catch(NullPointerException e) {
      LOGGER.log(Level.WARNING, "Invalid Content", e);
      return "";
    }
  }
  
  /**
   * Sets the content of the given entry to the given String.
   */
  public static void setContent(BaseContentEntry<?> entry, String content) {
    XmlBlob blob = new XmlBlob();
    blob.setBlob(content);
    TextConstruct textConstruct = new XhtmlTextConstruct(blob);
    entry.setContent(textConstruct);
  }
  
  /**
   * Returns a new Comparator that orders BaseContentEntry's based on
   * their updated times (earlier updated times come first).
   */
  public static Comparator<BaseContentEntry<?>> getUpdatedComparator() {
    return new UpdatedComparator(true);
  }
  
  /**
   * Returns a new Comparator that orders BaseContentEntry's based on
   * their updated times (later updated times come first).
   */
  public static Comparator<BaseContentEntry<?>> getReverseUpdatedComparator() {
    return new UpdatedComparator(false);
  }
  
  /**
   * Returns a new Comparator that orders BaseContentEntry's alphabetically
   * by their titles.
   */
  public static Comparator<BaseContentEntry<?>> getTitleComparator() {
    return new TitleComparator();
  }
  
  /**
   * Compares BaseContentEntry's based on their titles.
   */
  private static class TitleComparator implements Comparator<BaseContentEntry<?>> {
    
    /**
     * Returns a positive integer if {@code e1}'s title comes after {@code e2}'s
     * title alphabetically.
     */
    @Override
    public int compare(BaseContentEntry<?> e1, BaseContentEntry<?> e2) {
      return e1.getTitle().getPlainText().compareTo(e2.getTitle().getPlainText());
    }
  }
  
  /** 
   * Compares BaseContentEntry's based on when they were last updated.
   */
  private static class UpdatedComparator implements Comparator<BaseContentEntry<?>> {
    
    private boolean forward;
    
    public UpdatedComparator(boolean forward) {
      this.forward = forward;
    }
    
    /**
     * Orders two entries such that the more recently updated entry comes first.
     */
    @Override
    public int compare(BaseContentEntry<?> e1, BaseContentEntry<?> e2) {
      int compare = e1.getUpdated().compareTo(e2.getUpdated());
      return forward ? compare : -compare;
    }
  }
}
