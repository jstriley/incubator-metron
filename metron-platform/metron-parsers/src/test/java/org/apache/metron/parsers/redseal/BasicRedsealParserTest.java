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
package org.apache.metron.parsers.redseal;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.json.simple.JSONObject;
import org.junit.Test;

public class BasicRedsealParserTest {

    private BasicRedsealParser bbp = new BasicRedsealParser();

    public BasicRedsealParserTest() throws Exception {
        super();
    }

    @Test
    public void testEvent() {
        String testString = "<134>Jun 29 01:46:30 www.burnbook.com local0: SRM_SERVER [VENTS] [.server.services.customevents.EventAggregator.rallAnalysisComplete | ctor Timer] - EventAction=RedSeal Network Analysis | EventDate=Jun 29, 2016 1:46:30 AM EDT | EventName=HostMetricsEvent | DeviceVendor=RedSeal Networks, Inc. | DeviceProduct=RedSeal Platform | DeviceVersion=8.2.1 | RedSealServerName=www.burnbook.com | RedSealServerIPAddress=99.99.999.999 | HostName=www.burnbook.com | HostRedSealID=8aa5577asdf3d101asdf5460c8e9cdfc30 | AnalysisDate=Jun 29, 2016 12:51:33 AM EDT | PrimaryService=NetBIOS Session Service | OSVendor=Microsoft | OperatingSystem=Windows Server 2012 R2 | AttackDepth=-1 | Exposure=0 | Value=10 | ServicesCount=19 | VulnerabilityCount=281 | Risk=0 | DownstreamRisk=0 | Confidence=1 | Leapfroggable=false | Exploitable=false | PrimaryIp=99.99.99.99 | AccessibleFromUntrusted=false | HasAccessToCritical=false | END RSExternal event";

        List<JSONObject> result = bbp.parse(testString.getBytes());

        JSONObject jo = result.get(0);

        assertEquals(jo.get("priority") + "", "134");
        assertEquals(jo.get("timestamp") + "", "1467179190000");
        assertEquals(jo.get("hostname"), "www.burnbook.com");
        assertEquals(jo.get("syslog_facility"), "local0");
        assertEquals(jo.get("EventAction"), "RedSeal Network Analysis");
        assertEquals(jo.get("EventDate"), "Jun 29, 2016 1:46:30 AM EDT");
        assertEquals(jo.get("EventName"), "HostMetricsEvent");
        assertEquals(jo.get("DeviceVendor"), "RedSeal Networks, Inc.");
        assertEquals(jo.get("DeviceProduct"), "RedSeal Platform");
        assertEquals(jo.get("DeviceVersion"), "8.2.1");
        assertEquals(jo.get("RedSealServerName"), "www.burnbook.com");
        assertEquals(jo.get("RedSealServerIPAddress"), "99.99.999.999");
        assertEquals(jo.get("HostRedSealID"), "8aa5577asdf3d101asdf5460c8e9cdfc30");
        assertEquals(jo.get("AnalysisDate"), "Jun 29, 2016 12:51:33 AM EDT");
        assertEquals(jo.get("PrimaryService"), "NetBIOS Session Service");
        assertEquals(jo.get("OSVendor"), "Microsoft");
        assertEquals(jo.get("OperatingSystem"), "Windows Server 2012 R2");
        assertEquals(jo.get("AttackDepth"), "-1");
        assertEquals(jo.get("Exposure"), "0");
        assertEquals(jo.get("Value"), "10");
        assertEquals(jo.get("ServicesCount"), "19");
        assertEquals(jo.get("VulnerabilityCount"), "281");
        assertEquals(jo.get("Risk"), "0");
        assertEquals(jo.get("DownstreamRisk"), "0");
        assertEquals(jo.get("Confidence"), "1");
        assertEquals(jo.get("Leapfroggable"), "false");
        assertEquals(jo.get("Exploitable"), "false");
        assertEquals(jo.get("PrimaryIp"), "99.99.99.99");
        assertEquals(jo.get("AccessibleFromUntrusted"), "false");
        assertEquals(jo.get("HasAccessToCritical"), "false");
        assertEquals(jo.get("HostName"), "www.burnbook.com");

        System.out.println(result);
    }


    @Test
    public void testAudit1() {
        String testString = "<150>Jun 22 11:11:33 www.burnbook.com local2: [ aaronsamuels ] https user authenticated OK - initial access to /data/reports/vulnreporting - from remote host ' 99.999.99.999 '";

        List<JSONObject> result = bbp.parse(testString.getBytes());

        JSONObject jo = result.get(0);

        assertEquals(jo.get("priority") + "", "150");
        assertEquals(jo.get("timestamp") + "", "1466608293000");
        assertEquals(jo.get("hostname"), "www.burnbook.com");
        assertEquals(jo.get("syslog_facility"), "local2");
        assertEquals(jo.get("username"), "aaronsamuels");
        assertEquals(jo.get("uri_path"), "/data/reports/vulnreporting");
        assertEquals(jo.get("authentication_result"), "success");
        assertEquals(jo.get("ip_src_addr"), "99.999.99.999");
        assertEquals(jo.get("protocol"), "https");

        System.out.println(result);
    }

    @Test
    public void testAudit2() {
        String testString = "<150>Jun 22 13:29:33 www.burnbook.com local2: [ gretchenweiners ] user authenticated OK - from remote host ' 99.99.999.999 '";

        List<JSONObject> result = bbp.parse(testString.getBytes());
        JSONObject jo = result.get(0);

        assertEquals(jo.get("priority") + "", "150");
        assertEquals(jo.get("timestamp") + "", "1466616573000");
        assertEquals(jo.get("hostname"), "www.burnbook.com");
        assertEquals(jo.get("syslog_facility"), "local2");
        assertEquals(jo.get("username"), "gretchenweiners");
        assertEquals(jo.get("authentication_result"), "success");
        assertEquals(jo.get("ip_src_addr"), "99.99.999.999");

        System.out.println(result);
    }

    @Test
    public void testAudit3() {
        String testString = "<150>Jun 22 13:29:35 www.burnbook.com local2: [ JMS user connection authenticated for: [gretchenweiners] ]";

        List<JSONObject> result = bbp.parse(testString.getBytes());

        JSONObject jo = result.get(0);

        assertEquals(jo.get("priority") + "", "150");
        assertEquals(jo.get("timestamp") + "", "1466616575000");
        assertEquals(jo.get("hostname"), "www.burnbook.com");
        assertEquals(jo.get("syslog_facility"), "local2");
        assertEquals(jo.get("username"), "gretchenweiners");
        assertEquals(jo.get("authentication_result"), "success");
        assertEquals(jo.get("protocol"), "JMS");

        System.out.println(result);
    }

    @Test
    public void testAudit4() {
        String testString = "<150>Jun 8 09:31:27 www.burnbook.com local2: [ gretchenweiners ] user authentication FAILED - from remote host ' 99.999.9.999 '";

        List<JSONObject> result = bbp.parse(testString.getBytes());

        JSONObject jo = result.get(0);

        assertEquals(jo.get("priority") + "", "150");
        assertEquals(jo.get("timestamp") + "", "1465392687000");
        assertEquals(jo.get("hostname"), "www.burnbook.com");
        assertEquals(jo.get("syslog_facility"), "local2");
        assertEquals(jo.get("username"), "gretchenweiners");
        assertEquals(jo.get("authentication_result"), "failure");
        assertEquals(jo.get("ip_src_addr"), "99.999.9.999");

        System.out.println(result);
    }
    @Test
    public void testAudit5() {
        String testString = "<150>Jun 10 14:58:43 www.burnbook.com local2: [ gretchenweiners ] failed to do final environmental check for Actuate reports . (permission denied)";

        List<JSONObject> result = bbp.parse(testString.getBytes());

        JSONObject jo = result.get(0);

        assertEquals(jo.get("priority") + "", "150");
        assertEquals(jo.get("timestamp") + "", "1465585123000");
        assertEquals(jo.get("hostname"), "www.burnbook.com");
        assertEquals(jo.get("syslog_facility"), "local2");
        assertEquals(jo.get("username"), "gretchenweiners");
        assertEquals(jo.get("message"), "failed to do final environmental check for Actuate reports . (permission denied)");

        System.out.println(result);
    }

    @Test
    public void testServer() {
        String testString = "<134>Jun 29 23:02:00 www.burnbook.com local0: SRM_SERVER [INFO ] [com.redsealsys.srm.server.util.PurgeDataUtils.execute | Thread-58 ] - SQL:[ DROP TABLE IF EXISTS current_device_purge_id_temp ]";

        List<JSONObject> result = bbp.parse(testString.getBytes());

        JSONObject jo = result.get(0);

        assertEquals(jo.get("priority") + "", "134");
        assertEquals(jo.get("timestamp") + "", "1467255720000");
        assertEquals(jo.get("hostname"), "www.burnbook.com");
        assertEquals(jo.get("syslog_facility"), "local0");
        assertEquals(jo.get("message"), "SRM_SERVER [INFO ] [com.redsealsys.srm.server.util.PurgeDataUtils.execute | Thread-58 ] - SQL:[ DROP TABLE IF EXISTS current_device_purge_id_temp ]");

        System.out.println(result);
    }



    @Test
    public void testAnalysis() {
        String testString = "<142>Jun 26 04:54:11 www.burnbook.com local1: Data Collection Task: RANCID - us.nx1k - Completed - Task Detail: data type: Cisco NX-OS (8.2.1); communication type: SFTP; credential: gretchenweiners; execution: scheduled collection - Summary: All 55 succeeded - 55 (out of 55) devices or hosts imported (3 added 52 updated )";

        List<JSONObject> result = bbp.parse(testString.getBytes());

        JSONObject jo = result.get(0);

        assertEquals(jo.get("priority") + "", "142");
        assertEquals(jo.get("timestamp") + "", "1466931251000");
        assertEquals(jo.get("hostname"), "www.burnbook.com");
        assertEquals(jo.get("syslog_facility"), "local1");
        assertEquals(jo.get("message"), "Data Collection Task: RANCID - us.nx1k - Completed - Task Detail: data type: Cisco NX-OS (8.2.1); communication type: SFTP; credential: gretchenweiners; execution: scheduled collection - Summary: All 55 succeeded - 55 (out of 55) devices or hosts imported (3 added 52 updated )");

        System.out.println(result);
    }

    @Test
    public void testSystem() {
        String testString = "<158>Jun 7 10:41:12 www.burnbook.com local3: RedSeal 8.2.1 (Build-1107) running... Tue Jun 07 10:41:12 EDT 2016";

        List<JSONObject> result = bbp.parse(testString.getBytes());

        JSONObject jo = result.get(0);

        assertEquals(jo.get("priority") + "", "158");
        assertEquals(jo.get("timestamp") + "", "1465310472000");
        assertEquals(jo.get("hostname"), "www.burnbook.com");
        assertEquals(jo.get("syslog_facility"), "local3");
        assertEquals(jo.get("message"), "RedSeal 8.2.1 (Build-1107) running... Tue Jun 07 10:41:12 EDT 2016");

        System.out.println(result);
    }

}