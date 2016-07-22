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
package org.apache.metron.parsers.paloalto;

import org.json.simple.JSONObject;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import com.google.common.collect.ImmutableMap;

import static org.junit.Assert.*;

public class BasicPaloAltoFirewallParserTest {

    private BasicPaloAltoFirewallParser basicPaloAltoFirewallParser = new BasicPaloAltoFirewallParser();

    @Test
    public void assertThreatTuple() {

        basicPaloAltoFirewallParser.configure(ImmutableMap.of("dateFormat", "yyyy MMM dd HH:mm:ss"
                                                             ,"timezone" , "UTC"
                                                             )
                                             );

        String testString = "<11>Jan  5 05:38:59 PAN1.exampleCustomer.com 1,2015/01/05 05:38:58,0006C110285,THREAT,vulnerability,1,2015/01/05 05:38:58,10.0.0.115," +
                "216.0.10.198,0.0.0.0,0.0.0.0,EX-Allow,example\\user.name,,web-browsing,vsys1,internal,external,ethernet1/2,ethernet1/1,LOG-Default," +
                "2015/01/05 05:38:58,12031,1,54180,80,0,0,0x80004000,tcp,reset-both,\"ad.aspx?f=300x250&id=12;tile=1;ord=67AF705D60B1119C0F18BEA336F9\"," +
                "HTTP: IIS Denial Of Service Attempt(40019),any,high,client-to-server,347368099,0x0,10.0.0.0-10.255.255.255,US,0,,1200568889751109656,,";

        List<JSONObject> result = null;
        try {
            result = basicPaloAltoFirewallParser.parse(testString.getBytes());
        } catch (Exception e) {
            fail();
        }

        JSONObject json = result.get(0);

        //Compare all the fields
        assertEquals(json.get("timestamp"), 1451972339000L);
        assertEquals(json.get("priority"), "11");
        assertEquals(json.get("hostname"), "PAN1.exampleCustomer.com");
        assertEquals(json.get("future_use"), "1");
        assertEquals(json.get("receive_time"), "2015/01/05 05:38:58");
        assertEquals(json.get("serial_number"), "0006C110285");
        assertEquals(json.get("type"), "THREAT");
        assertEquals(json.get("subtype"), "vulnerability");
        assertEquals(json.get("future_use2"), "1");
        assertEquals(json.get("generated_time"), "2015/01/05 05:38:58");
        assertEquals(json.get("ip_src_addr"), "10.0.0.115");
        assertEquals(json.get("ip_dst_addr"), "216.0.10.198");
        assertEquals(json.get("nat_source_ip"), "0.0.0.0");
        assertEquals(json.get("nat_destination_ip"), "0.0.0.0");
        assertEquals(json.get("rule_name"), "EX-Allow");
        assertEquals(json.get("src_user_name"), "example\\user.name");
        assertEquals(json.get("application"), "web-browsing");
        assertEquals(json.get("virtual_system"), "vsys1");
        assertEquals(json.get("source_zone"), "internal");
        assertEquals(json.get("destination_zone"), "external");
        assertEquals(json.get("ingress_interface"), "ethernet1/2");
        assertEquals(json.get("egress_interface"), "ethernet1/1");
        assertEquals(json.get("log_forwarding_profile"), "LOG-Default");
        assertEquals(json.get("future_use3"), "2015/01/05 05:38:58");
        assertEquals(json.get("session_id"), "12031");
        assertEquals(json.get("repeat_count"), "1");
        assertEquals(json.get("ip_src_port"), "54180");
        assertEquals(json.get("ip_dst_port"), "80");
        assertEquals(json.get("nat_source_port"), "0");
        assertEquals(json.get("nat_destination_port"), "0");
        assertEquals(json.get("flags"), "0x80004000");
        assertEquals(json.get("protocol"), "tcp");
        assertEquals(json.get("action"), "reset-both");
        assertEquals(json.get("miscellaneous"), "\"ad.aspx?f=300x250&id=12;tile=1;ord=67AF705D60B1119C0F18BEA336F9\"");
        assertEquals(json.get("threat_id"), "HTTP: IIS Denial Of Service Attempt(40019)");
        assertEquals(json.get("category"), "any");
        assertEquals(json.get("severity"), "high");
        assertEquals(json.get("direction"), "client-to-server");
        assertEquals(json.get("sequence_number"), "347368099");
        assertEquals(json.get("action_flags"), "0x0");
        assertEquals(json.get("source_location"), "10.0.0.0-10.255.255.255");
        assertEquals(json.get("destination_location"), "US");
        assertEquals(json.get("future_use4"), "0");
        assertEquals(json.get("pcap_id"), "1200568889751109656");
    }

    @Test
    public void assertTrafficTuple() {

        basicPaloAltoFirewallParser.configure(ImmutableMap.of("dateFormat", "yyyy MMM dd HH:mm:ss"
                                                             ,"timezone" , "UTC"
                                                             )
                                             );

        String testString = "<14>Jan  5 12:51:34 PAN1.exampleCustomer.com 1,2015/01/05 12:51:33,0011C103117,TRAFFIC,end,1,2015/01/05 12:51:33,10.0.0.53,10.1.0.174," +
                "0.0.0.0,0.0.0.0,EX-EasyAV2,,,mssql-db,vsys1,v_external,v_internal,ethernet1/2,ethernet1/1,LOG-Default,2015/01/05 12:51:33,33621086,1,54266,40004," +
                "0,0,0x401c,tcp,allow,5325,3299,2026,25,2015/01/05 12:51:01,30,any,0,17754932075,0x0,10.0.0.0-10.255.255.255,10.0.0.0-10.255.255.255,0,11,14";

        List<JSONObject> result = null;
        try {
            result = basicPaloAltoFirewallParser.parse(testString.getBytes());
        } catch (Exception e) {
            fail();
        }

        JSONObject json = result.get(0);

        //Compare all the fields
        assertEquals(json.get("timestamp"),1451998294000L);
        assertEquals(json.get("priority"), "14");
        assertEquals(json.get("hostname"), "PAN1.exampleCustomer.com");
        assertEquals(json.get("future_use"), "1");
        assertEquals(json.get("receive_time"), "2015/01/05 12:51:33");
        assertEquals(json.get("serial_number"), "0011C103117");
        assertEquals(json.get("type"), "TRAFFIC");
        assertEquals(json.get("subtype"), "end");
        assertEquals(json.get("future_use2"), "1");
        assertEquals(json.get("generated_time"), "2015/01/05 12:51:33");
        assertEquals(json.get("ip_src_addr"), "10.0.0.53");
        assertEquals(json.get("ip_dst_addr"), "10.1.0.174");
        assertEquals(json.get("nat_source_ip"), "0.0.0.0");
        assertEquals(json.get("nat_destination_ip"), "0.0.0.0");
        assertEquals(json.get("rule_name"), "EX-EasyAV2");
        assertEquals(json.get("application"), "mssql-db");
        assertEquals(json.get("virtual_system"), "vsys1");
        assertEquals(json.get("source_zone"), "v_external");
        assertEquals(json.get("destination_zone"), "v_internal");
        assertEquals(json.get("ingress_interface"), "ethernet1/2");
        assertEquals(json.get("egress_interface"), "ethernet1/1");
        assertEquals(json.get("log_forwarding_profile"), "LOG-Default");
        assertEquals(json.get("future_use3"), "2015/01/05 12:51:33");
        assertEquals(json.get("session_id"), "33621086");
        assertEquals(json.get("repeat_count"), "1");
        assertEquals(json.get("ip_src_port"), "54266");
        assertEquals(json.get("ip_dst_port"), "40004");
        assertEquals(json.get("nat_source_port"), "0");
        assertEquals(json.get("nat_destination_port"), "0");
        assertEquals(json.get("flags"), "0x401c");
        assertEquals(json.get("protocol"), "tcp");
        assertEquals(json.get("action"), "allow");
        assertEquals(json.get("bytes"), "5325");
        assertEquals(json.get("bytes_sent"), "3299");
        assertEquals(json.get("bytes_received"), "2026");
        assertEquals(json.get("packets"), "25");
        assertEquals(json.get("start_time"), "2015/01/05 12:51:01");
        assertEquals(json.get("elapsed_time"), "30");
        assertEquals(json.get("category"), "any");
        assertEquals(json.get("future_use4"), "0");
        assertEquals(json.get("sequence_number"), "17754932075");
        assertEquals(json.get("action_flags"), "0x0");
        assertEquals(json.get("source_location"), "10.0.0.0-10.255.255.255");
        assertEquals(json.get("destination_location"), "10.0.0.0-10.255.255.255");
        assertEquals(json.get("future_use5"), "0");
        assertEquals(json.get("packets_sent"), "11");
        assertEquals(json.get("packets_received"), "14");
    }

    @Test
    public void assertConfigTuple() {

        basicPaloAltoFirewallParser.configure(ImmutableMap.of("dateFormat", "yyyy MMM dd HH:mm:ss"
                                                             ,"timezone" , "UTC"
                                                             )
                                             );

        String testString = "<14>Mar 24 18:36:14 PAN1.exampleCustomer.com 1,2016/03/24 18:36:14,003001112668,CONFIG,0,0,2016/03/24 18:36:14,10.255.255.255,,set," +
                "HarryPotter,Web,Succeeded, config mgt-config users HarryPotter preferences saved-log-query traffic Change-Mar25,8071,0x0,0,0,0,0,,SUNKUPAN1";

        List<JSONObject> result = null;
        try {
            result = basicPaloAltoFirewallParser.parse(testString.getBytes());
        } catch (Exception e) {
            fail();
        }

        JSONObject json = result.get(0);

        //Compare all the fields
        assertEquals(json.get("timestamp"), 1458844574000L);
        assertEquals(json.get("priority"), "14");
        assertEquals(json.get("hostname"), "PAN1.exampleCustomer.com");
        assertEquals(json.get("future_use"), "1");
        assertEquals(json.get("receive_time"), "2016/03/24 18:36:14");
        assertEquals(json.get("serial_number"), "003001112668");
        assertEquals(json.get("type"), "CONFIG");
        assertEquals(json.get("subtype"), "0");
        assertEquals(json.get("future_use2"), "0");
        assertEquals(json.get("generated_time"), "2016/03/24 18:36:14");
        assertEquals(json.get("host"), "10.255.255.255");
        assertEquals(json.get("command"), "set");
        assertEquals(json.get("admin"), "HarryPotter");
        assertEquals(json.get("client"), "Web");
        assertEquals(json.get("result"), "Succeeded");
        assertEquals(json.get("configuration_path"), " config mgt-config users HarryPotter preferences saved-log-query traffic Change-Mar25");
        assertEquals(json.get("sequence_number"), "8071");
        assertEquals(json.get("action_flags"), "0x0");
        assertEquals(json.get("device_group_hierarchy_level1"), "0");
        assertEquals(json.get("device_group_hierarchy_level2"), "0");
        assertEquals(json.get("device_group_hierarchy_level3"), "0");
        assertEquals(json.get("device_group_hierarchy_level4"), "0");
        assertEquals(json.get("device_name"), "SUNKUPAN1");
    }

    @Test
    public void assertSystemTuple() {

        basicPaloAltoFirewallParser.configure(ImmutableMap.of("dateFormat", "yyyy MMM dd HH:mm:ss"
                                                             ,"timezone" , "UTC"
                                                             )
                                             );

        String testString = "<14>Mar 25 00:00:56 PAN1.exampleCustomer.com 1,2016/03/25 00:00:56,003002112674,SYSTEM,general,0,2016/03/25 00:00:56,,general,,0,0," +
                "general,informational,User HarryPotter logged in via Web from 10.255.255.255 using http,156324,0x0,0,0,0,0,,SUNKUPAN1";

        List<JSONObject> result = null;
        try {
            result = basicPaloAltoFirewallParser.parse(testString.getBytes());
        } catch (Exception e) {
            fail();
        }

        JSONObject json = result.get(0);

        //Compare all the fields
        assertEquals(json.get("timestamp"), 1458864056000L);
        assertEquals(json.get("priority"), "14");
        assertEquals(json.get("hostname"), "PAN1.exampleCustomer.com");
        assertEquals(json.get("future_use"), "1");
        assertEquals(json.get("receive_time"), "2016/03/25 00:00:56");
        assertEquals(json.get("serial_number"), "003002112674");
        assertEquals(json.get("type"), "SYSTEM");
        assertEquals(json.get("subtype"), "general");
        assertEquals(json.get("future_use2"), "0");
        assertEquals(json.get("generated_time"), "2016/03/25 00:00:56");
        assertEquals(json.get("event_id"), "general");
        assertEquals(json.get("future_use3"), "0");
        assertEquals(json.get("future_use4"), "0");
        assertEquals(json.get("module"), "general");
        assertEquals(json.get("severity"), "informational");
        assertEquals(json.get("description"), "User HarryPotter logged in via Web from 10.255.255.255 using http");
        assertEquals(json.get("sequence_number"), "156324");
        assertEquals(json.get("action_flags"), "0x0");
        assertEquals(json.get("device_group_hierarchy_level1"), "0");
        assertEquals(json.get("device_group_hierarchy_level2"), "0");
        assertEquals(json.get("device_group_hierarchy_level3"), "0");
        assertEquals(json.get("device_group_hierarchy_level4"), "0");
        assertEquals(json.get("device_name"), "SUNKUPAN1");
    }

    @Test
    public void testEmpty() {
        String testString = "";
        List<JSONObject> result = null;
        boolean hitException = false;
        try {
            result = basicPaloAltoFirewallParser.parse(testString.getBytes());
        } catch (Exception e) {
            hitException = true;
        }
        assertTrue(hitException);
    }

    @Test
    public void testMalformed() {
        String testString = "<11>  Jan  5 05:3  5 9 PAN1.exampleCustomer .com 1,2015/01/05 05:38:58,0006C110285,THREAT,vulnerability,1,2015/01/05 05:38:58,10.0.0.115," +
                "216.0.10.198,0.0.0.0,0.0.0.0,EX-Allow,example\\user.name,,web-browsing,vsys1,internal,external,ethernet1/2,ethernet1/1,LOG-Default," +
                "2015/01/05 05:38:58,12031,1,54180,80,0,0,0x80004000,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,tcp,reset-both,\"ad.aspx?f=300x250&id=12;tile=1;ord=67AF705D60B1119C0F18BEA336F9\"," +
                "HTTP: IIS Denial Of Service Attempt(40019),any,high,client-to-server,347368099,0x0,10.0.0.0-10.255.255.255,US,0,,1200568889751109656,,";
        List<JSONObject> result = null;
        boolean hitException = false;
        try {
            result = basicPaloAltoFirewallParser.parse(testString.getBytes());
        } catch (Exception e) {
            hitException = true;
        }
        assertTrue(hitException);
    }

}
