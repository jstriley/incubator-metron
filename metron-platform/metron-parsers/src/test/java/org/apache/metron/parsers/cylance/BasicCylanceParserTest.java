/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.metron.parsers.cylance;

// IMPORT PACKAGES
import org.json.simple.JSONObject;
import org.junit.Test;
import java.util.List;
import static org.junit.Assert.*;

public class BasicCylanceParserTest {

  @Test
  public void testEventNameSystemSecurity() throws Exception {
    BasicCylanceParser cylanceParser = new BasicCylanceParser();
    String testString = "<116>Jul 8 17:48:40 sysloghost CylancePROTECT Event Type: Device, Event Name: SystemSecurity, Device Name: a0999b134871, Agent Version: 1.2.1350.541, IP Address: (291.390.9.143), MAC Address: (A9987B134871, CE9F7E54EAA1), Logged On Users: (harrypotter), OS: MAC OS X El Capitan 10.11.5 x64 10.11.5#015";

    List<JSONObject> result = null;
    try {
        result = cylanceParser.parse(testString.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
        fail();
    }

    JSONObject parsedJSON = result.get(0);
    System.out.println(parsedJSON);

    assertEquals(parsedJSON.get("source:type"), "cylance");
    assertEquals(parsedJSON.get("priority"), "116");
    assertEquals(parsedJSON.get("timestamp"), 1468000120000L);
    assertEquals(parsedJSON.get("hostname"), "sysloghost");
    assertEquals(parsedJSON.get("process"), "CylancePROTECT");
    assertEquals(parsedJSON.get("event_type"), "Device");
    assertEquals(parsedJSON.get("event_name"), "SystemSecurity");
    assertEquals(parsedJSON.get("device_name"), "a0999b134871");
    assertEquals(parsedJSON.get("agent_version"), "1.2.1350.541");
    assertEquals(parsedJSON.get("ip_address"), "291.390.9.143");
    assertEquals(parsedJSON.get("mac_address"), "A9987B134871, CE9F7E54EAA1");
    assertEquals(parsedJSON.get("logged_on_users"), "harrypotter");
    assertEquals(parsedJSON.get("os"), "MAC OS X El Capitan 10.11.5 x64 10.11.5");
  }

  @Test
  public void testEventNameResearchSaved() throws Exception {
    BasicCylanceParser cylanceParser = new BasicCylanceParser();
    String testString = "<116>Jul 8 17:47:42 sysloghost CylancePROTECT Event Type: ThreatClassification, Event Name: ResearchSaved, Threat Class: PUP, Threat Subclass: Adware, SHA256: E6D8C4F1484BB5T2G89PR9EC91048F4DE533DC3CB37C13021077DD8C564C81F9, MD5: 689A96F71161190A819X0X9D7341I9B#015";

    List<JSONObject> result = null;
    try {
        result = cylanceParser.parse(testString.getBytes());
    } catch (Exception e) {
        fail();
    }

    JSONObject parsedJSON = result.get(0);
    System.out.println(parsedJSON);

    assertEquals(parsedJSON.get("source:type"), "cylance");
    assertEquals(parsedJSON.get("priority"), "116");
    assertEquals(parsedJSON.get("timestamp"), 1468000062000L);
    assertEquals(parsedJSON.get("hostname"), "sysloghost");
    assertEquals(parsedJSON.get("process"), "CylancePROTECT");
    assertEquals(parsedJSON.get("event_type"), "ThreatClassification");
    assertEquals(parsedJSON.get("event_name"), "ResearchSaved");
    assertEquals(parsedJSON.get("threat_class"), "PUP");
    assertEquals(parsedJSON.get("threat_subclass"), "Adware");
    assertEquals(parsedJSON.get("sha256"), "E6D8C4F1484BB5T2G89PR9EC91048F4DE533DC3CB37C13021077DD8C564C81F9");
    assertEquals(parsedJSON.get("md5"), "689A96F71161190A819X0X9D7341I9B");
  }

  @Test
  public void testEventNameResearchSaved2() throws Exception {
    BasicCylanceParser cylanceParser = new BasicCylanceParser();
    String testString = "<116>Jul 8 17:47:22 sysloghost CylancePROTECT message repeated 2 times: [Event Type: ThreatClassification, Event Name: ResearchSaved, Threat Class: PUP, Threat Subclass: Adware, SHA256: E6D8C4F1234BB3F1B25FA9EC91048F4DE098DC3CB37C13021077DD8C765C81F9, MD5: 689A96F71098726A8193D8P0X8341E6B#015]";

    List<JSONObject> result = null;
    try {
        result = cylanceParser.parse(testString.getBytes());
    } catch (Exception e) {
        fail();
    }

    JSONObject parsedJSON = result.get(0);
    System.out.println(parsedJSON);

    assertEquals(parsedJSON.get("source:type"), "cylance");
    assertEquals(parsedJSON.get("priority"), "116");
    assertEquals(parsedJSON.get("timestamp"), 1468000042000L);
    assertEquals(parsedJSON.get("hostname"), "sysloghost");
    assertEquals(parsedJSON.get("process"), "CylancePROTECT");
    assertEquals(parsedJSON.get("repeat_count"), "2");
    assertEquals(parsedJSON.get("event_type"), "ThreatClassification");
    assertEquals(parsedJSON.get("event_name"), "ResearchSaved");
    assertEquals(parsedJSON.get("threat_class"), "PUP");
    assertEquals(parsedJSON.get("threat_subclass"), "Adware");
    assertEquals(parsedJSON.get("sha256"), "E6D8C4F1234BB3F1B25FA9EC91048F4DE098DC3CB37C13021077DD8C765C81F9");
    assertEquals(parsedJSON.get("md5"), "689A96F71098726A8193D8P0X8341E6B");
  }

  @Test
  public void testEventNameCorruptFound() throws Exception {
    BasicCylanceParser cylanceParser = new BasicCylanceParser();
    String testString = "<116>Jul 8 17:50:30 sysloghost CylancePROTECT Event Type: Threat, Event Name: corrupt_found, Device Name: DEP5CG6987D2F, IP Address: (222.765.9.8, 2600:1003:b02c:f691:7c70:e3d0:1303:ff9c, 2600:1003:b02c:f691:80f4:59ba:8412:2648, 234.19.56.109), File Name: olivanders, Path: c:\\program files (x86)\\chamberofsecrets\\net wand provider for harry\\15.00\\help\\, Drive Type: None, SHA256: AD123456F9B97E4EEAEF987654143FEFAB39106B707857C48PB085B8AD6E90E6, MD5: , Status: Corrupt, Cylance Score: 0, Found Date: 7/8/2016 5:50:30 PM, File Type: Executable, Is Running: False, Auto Run: False, Detected By: FileWatcher#015";

    List<JSONObject> result = null;
    try {
        result = cylanceParser.parse(testString.getBytes());
    } catch (Exception e) {
        fail();
    }

    JSONObject parsedJSON = result.get(0);
    System.out.println(parsedJSON);

    assertEquals(parsedJSON.get("source:type"), "cylance");
    assertEquals(parsedJSON.get("priority"), "116");
    assertEquals(parsedJSON.get("timestamp"), 1468000230000L);
    assertEquals(parsedJSON.get("hostname"), "sysloghost");
    assertEquals(parsedJSON.get("process"), "CylancePROTECT");
    assertEquals(parsedJSON.get("event_type"), "Threat");
    assertEquals(parsedJSON.get("event_name"), "corrupt_found");
    assertEquals(parsedJSON.get("device_name"), "DEP5CG6987D2F");
    assertEquals(parsedJSON.get("ip_address"), "222.765.9.8, 2600:1003:b02c:f691:7c70:e3d0:1303:ff9c, 2600:1003:b02c:f691:80f4:59ba:8412:2648, 234.19.56.109");
    assertEquals(parsedJSON.get("file_name"), "olivanders");
    assertEquals(parsedJSON.get("path"), "c:\\program files (x86)\\chamberofsecrets\\net wand provider for harry\\15.00\\help\\");
    assertEquals(parsedJSON.get("drive_type"), "None");
    assertEquals(parsedJSON.get("sha256"), "AD123456F9B97E4EEAEF987654143FEFAB39106B707857C48PB085B8AD6E90E6");
    assertEquals(parsedJSON.get("status"), "Corrupt");
    assertEquals(parsedJSON.get("cylance_score"), "0");
    assertEquals(parsedJSON.get("found_date"), "7/8/2016 5:50:30 PM");
    assertEquals(parsedJSON.get("file_type"), "Executable");
    assertEquals(parsedJSON.get("is_running"), "False");
    assertEquals(parsedJSON.get("auto_run"), "False");
    assertEquals(parsedJSON.get("detected_by"), "FileWatcher");
  }
}
