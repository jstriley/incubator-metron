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
package org.apache.metron.parsers.bluecoatcim;

import org.apache.metron.parsers.activedirectory.ActiveDirectoryParser;
import org.json.simple.JSONObject;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class BasicBluecoatCIMParserTest {

	private BasicBluecoatCIMParser bbcp = new BasicBluecoatCIMParser();

	@Test
	public void testBluecoatCIMLine() {
		String testString = "<13>May 26 13:13:58 abcproxy11a.abc.letters.com bcproxysg|date=2016-05-26|time=1 13:58|duration=8|src_ip=12.32.42.52|user=-|cs_auth_group=-|x_exception_id=authentication_failed|filter_result=DENIED|category=\"Web Ads/Analytics\"|http_referrer=-|status=407|action=TCP_DENIED|http_method=CONNECT|http_content_type=-|cs_uri_scheme=tcp|dest=n2.test.com|uri_port=123|uri_path=/|uri_query=-|uri_extension=-|http_user_agent=Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/12.0.3456.78 Safari/537.36|dest_ip=12.34.56.78|bytes_in=302|bytes_out=215|x_virus_id=-|x_bluecoat_application_name=\"none\"|x_bluecoat_application_operation=\"none\"|target_ip=12.34.432.10|proxy_connect_type=Explicit|proxy_name=\"abcproxy11a\"|proxy_ip=123.456.789.876|proxy_src_ip=-|dest_duration=-|x_rs_certificate_validate_status=-|x_rs_certificate_observed_errors=-|x_cs_ocsp_error=-|x_rs_ocsp_error=-|x_rs_connection_negotiated_ssl_version=-|x_rs_connection_negotiated_cipher=none|x_rs_connection_negotiated_cipher_size=-|x_rs_certificate_hostname=-|x_rs_certificate_hostname_category=-|x_cs_connection_negotiated_ssl_version=-|x_cs_connection_negotiated_cipher=none|x_cs_connection_negotiated_cipher_size=-|x_cs_certificate_subject=-|cs_realm=proxy_AD_realm|cs_auth_type=Certificate|x_auth_credential_type=-|%0D%0A ";

		try{
			List<JSONObject> result = bbcp.parse(testString.getBytes());

			JSONObject jo = result.get(0);

			assertEquals(jo.get("date"), "2016-05-26");
			assertEquals(jo.get("cs_uri_scheme"), "tcp");
			assertEquals(jo.get("dest"), "n2.test.com");
			assertEquals(jo.get("filter_result"), "DENIED");
			assertEquals(jo.get("http_method"), "CONNECT");
			assertEquals(jo.get("uri_path"), "/");
			assertEquals(jo.get("cs_realm"), "proxy_AD_realm");
			assertEquals(jo.get("action"), "TCP_DENIED");
			assertEquals(jo.get("cs_auth_type"), "Certificate");
			assertEquals(jo.get("priority"), "13");
			assertEquals(jo.get("proxy_name"), "abcproxy11a");
			assertEquals(jo.get("bytes_out"), "215");
			assertEquals(jo.get("ip_dst_addr"), "12.34.56.78");
			assertEquals(jo.get("proxy_connect_type"), "Explicit");
			assertEquals(jo.get("x_rs_connection_negotiated_cipher"), "none");
			assertEquals(jo.get("status"), "407");
			assertEquals(jo.get("bytes_in"), "302");
			assertEquals(jo.get("x_cs_connection_negotiated_cipher"), "none");
			assertEquals(jo.get("http_user_agent"), "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/12.0.3456.78 Safari/537.36");
			assertEquals(jo.get("duration"), "8");
			assertEquals(jo.get("ip_src_addr"), "12.32.42.52");
			assertEquals(jo.get("src_ip"), "12.32.42.52");
			assertEquals(jo.get("x_bluecoat_application_name"), "none");
			assertEquals(jo.get("timestamp").toString(), "1464268438000");
			assertEquals(jo.get("proxy_ip"), "123.456.789.876");
			assertEquals(jo.get("x_exception_id"), "authentication_failed");
			assertEquals(jo.get("x_bluecoat_application_operation"), "none");
			assertEquals(jo.get("target_ip"), "12.34.432.10");
			assertEquals(jo.get("uri_port"), "123");
			assertEquals(jo.get("time"), "1 13:58");
			assertEquals(jo.get("category"), "Web Ads/Analytics");
		}
		catch (Exception e){
			fail();
		}
	}

	@Test
	public void valueContainsPipes(){
		String containsExtraPipes = "<13>May 26 13:13:58 abcproxy11a.abc.letters.com bcproxysg|date=2016-05-26|time=1 13:59|duration=116|src_ip=01.234.56.789|user=abc123|cs_auth_group=ABC\\GR%20GG%20ABC%20USR%20Sopranoweb|x_exception_id=-|filter_result=OBSERVED|category=\"Web Ads/Analytics\"|http_referrer=http://optimized-by.rubiconproject.com/a/1234/11111/111111-11.html?&cb=0.15817356504369195&tk_st=1&rf=http%3A//my.xfinity.com/%3FCCT%3D53BA3D76CB1473BFF49C79FE4AA86DFF1EE2DE626F409A59DF3627E6D3E61E7589F04CDFB710C1AA4ACF47607252791020D2D26F72D12F9CC20696585816%26cid%3Dcust%26amcid%3DSEG_MYACCOUNT%26ts%3D3&rp_s=c&p_pos=atf&p_screen_res=1280x1024|status=200|action=TCP_MISS|http_method=GET|http_content_type=image/gif|cs_uri_scheme=http|dest=dt.apple.com|uri_port=80|uri_path=/dt|uri_query=?asId=2faaaa32-2365-aa00-bd39-00aa904ea2aa&tv={c:dOFvEi,pingTime:15,time:18377,type:p,fc:0,rt:1,cb:0,np:1,th:0,es:0,gm:0,fif:0,slTimes:{i:17824,o:554,n:1179,pp:0,pm:0,gpp:0,gpm:0,gi:0,go:0,gn:18378,fi:0,fo:0,fn:18378},slEvents:[{sl:n,fsl:fn,gsl:gn,t:874,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:-1,obst:0,th:0,reas:,cmps:1,bkn:{piv:[1166~1],as:[1166~300.250]}},{sl:i,fsl:fn,gsl:gn,t:1179,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:50,obst:0,th:0,reas:,cmps:1,bkn:{piv:[597~50],as:[597~300.250]}},{sl:o,fsl:fn,gsl:gn,t:1776,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:0,obst:0,th:0,reas:,cmps:1,bkn:{piv:[200~0],as:[200~300.250]}},{sl:i,fsl:fn,gsl:gn,t:1976,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:50,obst:0,th:0,reas:,cmps:1,bkn:{piv:[700~50],as:[700~300.250]}},{sl:o,fsl:fn,gsl:gn,t:2676,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:0,obst:0,th:0,reas:,cmps:1,bkn:{piv:[200~0],as:[200~300.250]}},{sl:i,fsl:fn,gsl:gn,t:2876,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:50,obst:0,th:0,reas:,cmps:1,bkn:{piv:[13385~50],as:[13385~300.250]}},{sl:o,fsl:fn,gsl:gn,t:16261,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:0,obst:0,th:0,reas:,cmps:1,bkn:{piv:[154~0],as:[154~300.250]}},{sl:i,fsl:fn,gsl:gn,t:16415,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:50,obst:0,th:0,reas:,cmps:1,bkn:{piv:[1964~50],as:[1964~300.250]}}],slEventCount:8,em:true,fr:false,uf:1,e:,tt:jload,dtt:209,fm:pMktnSV+11|121|122|123*.7389|1231|1232|1233|13.7389|131|132|133|14|15|16|17|18|191|1a1|1b1,idMap:123*,fx:21.0.0|21.0.0.216}&br=c|uri_extension=-|http_user_agent=Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.87 Safari/537.36|dest_ip=69.172.216.111|bytes_in=266|bytes_out=6705|x_virus_id=-|x_bluecoat_application_name=\"none\"|x_bluecoat_application_operation=\"none\"|target_ip=12.34.567.89|proxy_connect_type=Explicit|proxy_name=\"abcproxy01p\"|proxy_ip=22.33.444.55|proxy_src_ip=111.22.44.777|dest_duration=84|x_rs_certificate_validate_status=-|x_rs_certificate_observed_errors=-|x_cs_ocsp_error=-|x_rs_ocsp_error=-|x_rs_connection_negotiated_ssl_version=-|x_rs_connection_negotiated_cipher=none|x_rs_connection_negotiated_cipher_size=-|x_rs_certificate_hostname=-|x_rs_certificate_hostname_category=-|x_cs_connection_negotiated_ssl_version=-|x_cs_connection_negotiated_cipher=none|x_cs_connection_negotiated_cipher_size=-|x_cs_certificate_subject=-|cs_realm=proxy_AD_realm|cs_auth_type=Certificate|x_auth_credential_type=Kerberos|%0D%0A";

		try {
			List<JSONObject> result = bbcp.parse(containsExtraPipes.getBytes());
			JSONObject json = result.get(0);
			assertEquals(json.get("date"), "2016-05-26");
			assertEquals(json.get("cs_uri_scheme"), "http");
			assertEquals(json.get("dest"), "dt.apple.com");
			assertEquals(json.get("original_string"), containsExtraPipes);
			assertEquals(json.get("filter_result"), "OBSERVED");
			assertEquals(json.get("http_method"), "GET");
			assertEquals(json.get("uri_path"), "/dt");
			assertEquals(json.get("cs_realm"), "proxy_AD_realm");
			assertEquals(json.get("action"), "TCP_MISS");
			assertEquals(json.get("cs_auth_type"), "Certificate");
			assertEquals(json.get("cs_auth_group"), "ABC\\GR%20GG%20ABC%20USR%20Sopranoweb");
			assertEquals(json.get("priority"), "13");
			assertEquals(json.get("proxy_name"), "abcproxy01p");
			assertEquals(json.get("uri_query"), "?asId=2faaaa32-2365-aa00-bd39-00aa904ea2aa&tv={c:dOFvEi,pingTime:15,time:18377,type:p,fc:0,rt:1,cb:0,np:1,th:0,es:0,gm:0,fif:0,slTimes:{i:17824,o:554,n:1179,pp:0,pm:0,gpp:0,gpm:0,gi:0,go:0,gn:18378,fi:0,fo:0,fn:18378},slEvents:[{sl:n,fsl:fn,gsl:gn,t:874,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:-1,obst:0,th:0,reas:,cmps:1,bkn:{piv:[1166~1],as:[1166~300.250]}},{sl:i,fsl:fn,gsl:gn,t:1179,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:50,obst:0,th:0,reas:,cmps:1,bkn:{piv:[597~50],as:[597~300.250]}},{sl:o,fsl:fn,gsl:gn,t:1776,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:0,obst:0,th:0,reas:,cmps:1,bkn:{piv:[200~0],as:[200~300.250]}},{sl:i,fsl:fn,gsl:gn,t:1976,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:50,obst:0,th:0,reas:,cmps:1,bkn:{piv:[700~50],as:[700~300.250]}},{sl:o,fsl:fn,gsl:gn,t:2676,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:0,obst:0,th:0,reas:,cmps:1,bkn:{piv:[200~0],as:[200~300.250]}},{sl:i,fsl:fn,gsl:gn,t:2876,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:50,obst:0,th:0,reas:,cmps:1,bkn:{piv:[13385~50],as:[13385~300.250]}},{sl:o,fsl:fn,gsl:gn,t:16261,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:0,obst:0,th:0,reas:,cmps:1,bkn:{piv:[154~0],as:[154~300.250]}},{sl:i,fsl:fn,gsl:gn,t:16415,wc:181.78.1081.916,ac:NaN.NaN.300.250,am:i,cc:...,piv:50,obst:0,th:0,reas:,cmps:1,bkn:{piv:[1964~50],as:[1964~300.250]}}],slEventCount:8,em:true,fr:false,uf:1,e:,tt:jload,dtt:209,fm:pMktnSV+11|121|122|123*.7389|1231|1232|1233|13.7389|131|132|133|14|15|16|17|18|191|1a1|1b1,idMap:123*,fx:21.0.0|21.0.0.216}&br=c");
			assertEquals(json.get("bytes_out"), "6705");
			assertEquals(json.get("dest_ip"), "69.172.216.111");
			assertEquals(json.get("http_referrer"), "http://optimized-by.rubiconproject.com/a/1234/11111/111111-11.html?&cb=0.15817356504369195&tk_st=1&rf=http%3A//my.xfinity.com/%3FCCT%3D53BA3D76CB1473BFF49C79FE4AA86DFF1EE2DE626F409A59DF3627E6D3E61E7589F04CDFB710C1AA4ACF47607252791020D2D26F72D12F9CC20696585816%26cid%3Dcust%26amcid%3DSEG_MYACCOUNT%26ts%3D3&rp_s=c&p_pos=atf&p_screen_res=1280x1024");
			assertEquals(json.get("proxy_connect_type"), "Explicit");
			assertEquals(json.get("x_rs_connection_negotiated_cipher"), "none");
			assertEquals(json.get("status"), "200");
			assertEquals(json.get("bytes_in"), "266");
			assertEquals(json.get("x_auth_credential_type"), "Kerberos");
			assertEquals(json.get("x_cs_connection_negotiated_cipher"), "none");
			assertEquals(json.get("http_user_agent"), "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.87 Safari/537.36");
			assertEquals(json.get("duration"), "116");
			assertEquals(json.get("src_ip"), "01.234.56.789");
			assertEquals(json.get("ip_dst_addr"), "69.172.216.111");
			assertEquals(json.get("http_content_type"), "image/gif");
			assertEquals(json.get("x_bluecoat_application_name"), "none");
			assertEquals(json.get("timestamp").toString(), "1464268438000");
			assertEquals(json.get("proxy_ip"), "22.33.444.55");
			assertEquals(json.get("proxy_src_ip"), "111.22.44.777");
			assertEquals(json.get("dest_duration"), "84");
			assertEquals(json.get("x_bluecoat_application_operation"), "none");
			assertEquals(json.get("target_ip"), "12.34.567.89");
			assertEquals(json.get("uri_port"), "80");
			assertEquals(json.get("time"), "1 13:59");
			assertEquals(json.get("category"), "Web Ads/Analytics");
			assertEquals(json.get("user"), "abc123");
		} catch (Exception e) {
			fail();
		}
	}

	@Test
	public void testDoubleSpaceLine() {
		BasicBluecoatCIMParser parser = new BasicBluecoatCIMParser();
		String testString = "<13>Jul  5 09:14:41 kdcproxy05p.kdc.capitalone.com bcproxysg|date=2016-07-05|time=1 14:41|duration=85|src_i\n" +
			"p=10.148.24.95|user=err144|cs_auth_group=COF\\GR%20GG%20COF%20USR%20Caponeweb|x_exception_id=-|filter_result=OBSERVED|category=\"Business/Economy\"|http_referrer=-|status=200|action=TCP_NC_MIS\n" +
			"S|http_method=GET|http_content_type=text/xml;charset=utf-8|cs_uri_scheme=http|url=st.videojam.tv/VideoJamAdService/getCreative|dest=st.videojam.tv|uri_port=80|uri_path=/VideoJamAdService/getCreative|uri_query=?CreativeTagId=1430&w=320&h=250&ref=https%3A%2F%2Fwww.yahoo.com&cb=56815342605113980000|uri_extension=-|http_user_agent=Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36|dest_ip=45.55.120.153|bytes_in=1384|bytes_out=5508|x_virus_id=-|x_bluecoat_application_name=\"none\"|x_bluecoat_application_operation=\"none\"|target_ip=10.37.130.14|proxy_connect_type=Explicit|proxy_name=\"kdcproxy05p\"|proxy_ip=10.37.130.14|proxy_src_ip=199.244.214.104|dest_duration=30|x_rs_certificate_validate_status=-|x_rs_certificate_observed_errors=-|x_cs_ocsp_error=-|x_rs_ocsp_error=-|x_rs_connection_negotiated_ssl_version=-|x_rs_connection_negotiated_cipher=none|x_rs_connection_negotiated_cipher_size=-|x_rs_certificate_hostname=-|x_rs_certificate_hostname_category=-|x_cs_connection_negotiated_ssl_version=-|x_cs_connection_negotiated_cipher=none|x_cs_connection_negotiated_cipher_size=-|x_cs_certificate_subject=-|cs_realm=proxy_AD_realm|cs_auth_type=Certificate|x_auth_credential_type=Kerberos|%0D%0A";
		List<JSONObject> result = null;
		try {
			result = parser.parse(testString.getBytes());
			System.out.println(result.get(0));
		} catch (Exception e) {
		}
		assertNotNull(result);
	}

	@Test
	public void testEmptyLine() {
		BasicBluecoatCIMParser parser = new BasicBluecoatCIMParser();
		String testString = "";
		List<JSONObject> result = null;
		try {
			result = parser.parse(testString.getBytes());
			System.out.println(result.get(0));
		} catch (Exception e) {
		}
		assertNull(result);
	}

}
