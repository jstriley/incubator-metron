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

package org.apache.metron.parsers.windowsyslogjson;

import org.apache.metron.parsers.windowssyslogjson.WindowsSyslogJSONParser;
import org.json.simple.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import static org.junit.Assert.*;

public class WindowsSyslogJSONParserTest {

//	private final String dateFormat = "yyyy MMM dd HH:mm:ss";
//	private final String timestampField = "timestamp_string";

	private static final Logger LOGGER = LoggerFactory
			.getLogger(WindowsSyslogJSONParserTest.class);

	public WindowsSyslogJSONParserTest() throws Exception {
		super();
	}
	
	private Map<String, Object> parserConfig;

	@Before
	public void setup() {
		parserConfig = new HashMap<>();
		parserConfig.put("grokPath", "../metron-parsers/src/main/resources/patterns/unixsyslog5424");
		parserConfig.put("patternLabel", "UNIXSYSLOG5424");
		parserConfig.put("timestampField", "timestamp_string");
		parserConfig.put("dateFormat", "yyyy-MM-dd'T'HH:mm:ss.SSS");
	}

	@Test
	public void testParseLine() throws Exception {
		//Set up parser, parse message
		WindowsSyslogJSONParser parser = new WindowsSyslogJSONParser();
		parser.configure(parserConfig);
		//parser.withDateFormat(dateFormat).withTimestampField(timestampField);
		String testString = "<1>1 2016-07-27T21:02:44.310311Z 10.14.56.249 whammi 0 - - {\"Category\":\"\",\"CategoryString\":\"Logon\",\"ComputerName\":\"VDCPFSTTWEB02.cof.ds.capitalone.com\",\"Data\":\"\",\"EventCode\":\"\",\"EventIdentifier\":\"\",\"EventType\":\"\",\"InsertionStrings\":\"\",\"Logfile\":\"Security\",\"Message\":\"An account was successfully logged on.\\r\\n\\r\\nSubject:\\r\\n\\tSecurity ID:\\t\\tS-1-0-0\\r\\n\\tAccount Name:\\t\\t-\\r\\n\\tAccount Domain:\\t\\t-\\r\\n\\tLogon ID:\\t\\t0x0\\r\\n\\r\\nLogon Type:\\t\\t\\t3\\r\\n\\r\\nNew Logon:\\r\\n\\tSecurity ID:\\t\\tS-1-5-21-99512129-1830164216-1097030630-547334\\r\\n\\tAccount Name:\\t\\tKED578\\r\\n\\tAccount Domain:\\t\\tCOF\\r\\n\\tLogon ID:\\t\\t0x2c9fa027\\r\\n\\tLogon GUID:\\t\\t{00000000-0000-0000-0000-000000000000}\\r\\n\\r\\nProcess Information:\\r\\n\\tProcess ID:\\t\\t0x0\\r\\n\\tProcess Name:\\t\\t-\\r\\n\\r\\nNetwork Information:\\r\\n\\tWorkstation Name:\\tCUSATX165226\\r\\n\\tSource Network Address:\\t10.218.217.133\\r\\n\\tSource Port:\\t\\t6169\\r\\n\\r\\nDetailed Authentication Information:\\r\\n\\tLogon Process:\\t\\tNtLmSsp \\r\\n\\tAuthentication Package:\\tNTLM\\r\\n\\tTransited Services:\\t-\\r\\n\\tPackage Name (NTLM only):\\tNTLM V2\\r\\n\\tKey Length:\\t\\t0\\r\\n\\r\\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\\r\\n\\r\\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\\r\\n\\r\\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\\r\\n\\r\\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\\r\\n\\r\\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\\r\\n\\r\\nThe authentication information fields provide detailed information about this specific logon request.\\r\\n\\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\\r\\n\\t- Transited services indicate which intermediate services have participated in this logon request.\\r\\n\\t- Package name indicates which sub-protocol was used among the NTLM protocols.\\r\\n\\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\",\"RecordNumber\":214981812,\"SourceName\":\"Microsoft-Windows-Security-Auditing\",\"TimeGenerated\":\"20160727210240.818850-000\",\"TimeWritten\":\"20160727210240.818850-000\",\"Type\":\"Audit Success\",\"User\":\"\",\"Host\":\"10.14.56.249\"}";
		List<JSONObject> result = parser.parse(testString.getBytes());
		JSONObject parsedJSON = result.get(0);

		JSONObject json = parsedJSON;



		// ensure json is not null
		assertNotNull(json);
		// ensure json is not empty
		assertTrue(!json.isEmpty());

		Iterator iter = json.entrySet().iterator();

		// ensure there are no null keys
		while (iter.hasNext()) {
			Map.Entry entry = (Map.Entry) iter.next();
			assertNotNull(entry);

			String key = (String) entry.getKey();
			assertNotNull(key);
		}

		assertEquals(1, json.get("priority"));
		assertEquals(1, json.get("syslog_version")); // FIXME
		assertEquals("10.14.56.249", json.get("hostname"));

		Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		cal.set(Calendar.YEAR, 2016);
		cal.set(Calendar.MONTH, Calendar.JULY);
		cal.set(Calendar.DAY_OF_MONTH, 27);
		cal.set(Calendar.HOUR_OF_DAY, 21);
		cal.set(Calendar.MINUTE, 2);
		cal.set(Calendar.SECOND, 44);
		cal.set(Calendar.MILLISECOND, 310);
		assertEquals(cal.getTime().getTime(), json.get("timestamp"));

		assertEquals("whammi", json.get("app_name"));
		assertEquals(0, json.get("process_id"));
		assertNull(json.get("message_id"));
		assertNull(json.get("structured_data"));

		// Now test data from JSON message body
		assertNull(json.get("category"));
		assertNull(json.get("data"));
		assertNull(json.get("event_code"));
		assertNull(json.get("event_identifier"));
		assertNull(json.get("event_type"));
		assertNull(json.get("insertion_strings"));
		assertNull(json.get("CategoryString"));
		assertEquals("Logon", json.get("category_string"));
		assertEquals("VDCPFSTTWEB02.cof.ds.capitalone.com", json.get("computer_name"));
		assertEquals("Security", json.get("logfile"));
		assertEquals("An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\t-\r\n\tAccount Domain:\t\t-\r\n\tLogon ID:\t\t0x0\r\n\r\nLogon Type:\t\t\t3\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-99512129-1830164216-1097030630-547334\r\n\tAccount Name:\t\tKED578\r\n\tAccount Domain:\t\tCOF\r\n\tLogon ID:\t\t0x2c9fa027\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x0\r\n\tProcess Name:\t\t-\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tCUSATX165226\r\n\tSource Network Address:\t10.218.217.133\r\n\tSource Port:\t\t6169\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tNtLmSsp \r\n\tAuthentication Package:\tNTLM\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\tNTLM V2\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.", json.get("message"));
		assertEquals(214981812l, json.get("record_number"));
		assertEquals("Microsoft-Windows-Security-Auditing", json.get("source_name"));
		assertEquals("20160727210240.818850-000", json.get("time_generated"));
		assertEquals("20160727210240.818850-000", json.get("time_written"));
		assertEquals("Audit Success", json.get("type"));
		assertNull(json.get("user"));
		assertEquals("10.14.56.249", json.get("host"));
	}

	/**
	 * Checks the input JSON object for any null keys. If a particular value in the JSONObject
	 * is another JSONObject, then recursively call this method again for the nested JSONObject
	 *
	 * @param jsonObj: the input JSON object for which to check null keys
	 */
	private void testKeysNotNull(JSONObject jsonObj) {
		for (Object key : jsonObj.keySet()) {
			assertNotNull(key);
			Object jsonValue = jsonObj.get(key);
			if (jsonValue.getClass().equals(JSONObject.class)) {
				testKeysNotNull((JSONObject) jsonValue);
			}
		}
	}
	@Test
	public void testEmptyLine() {
		//Set up parser, parse message
		WindowsSyslogJSONParser parser = new WindowsSyslogJSONParser();
		parser.configure(parserConfig);
		//parser.withDateFormat(dateFormat).withTimestampField(timestampField);
		String testString = "";
		List<JSONObject> result = null;
		try {
			result = parser.parse(testString.getBytes());
		} catch (Exception e) {
		}
		assertNull(result);
	}

	public static void main (String[] args) {
		System.out.println("<1>1 2016-07-27T21:02:44.310311Z 10.14.56.249 whammi 0 - - {\"Category\":\"\",\"CategoryString\":\"Logon\",\"ComputerName\":\"VDCPFSTTWEB02.cof.ds.capitalone.com\",\"Data\":\"\",\"EventCode\":\"\",\"EventIdentifier\":\"\",\"EventType\":\"\",\"InsertionStrings\":\"\",\"Logfile\":\"Security\",\"Message\":\"An account was successfully logged on.\\r\\n\\r\\nSubject:\\r\\n\\tSecurity ID:\\t\\tS-1-0-0\\r\\n\\tAccount Name:\\t\\t-\\r\\n\\tAccount Domain:\\t\\t-\\r\\n\\tLogon ID:\\t\\t0x0\\r\\n\\r\\nLogon Type:\\t\\t\\t3\\r\\n\\r\\nNew Logon:\\r\\n\\tSecurity ID:\\t\\tS-1-5-21-99512129-1830164216-1097030630-547334\\r\\n\\tAccount Name:\\t\\tKED578\\r\\n\\tAccount Domain:\\t\\tCOF\\r\\n\\tLogon ID:\\t\\t0x2c9fa027\\r\\n\\tLogon GUID:\\t\\t{00000000-0000-0000-0000-000000000000}\\r\\n\\r\\nProcess Information:\\r\\n\\tProcess ID:\\t\\t0x0\\r\\n\\tProcess Name:\\t\\t-\\r\\n\\r\\nNetwork Information:\\r\\n\\tWorkstation Name:\\tCUSATX165226\\r\\n\\tSource Network Address:\\t10.218.217.133\\r\\n\\tSource Port:\\t\\t6169\\r\\n\\r\\nDetailed Authentication Information:\\r\\n\\tLogon Process:\\t\\tNtLmSsp \\r\\n\\tAuthentication Package:\\tNTLM\\r\\n\\tTransited Services:\\t-\\r\\n\\tPackage Name (NTLM only):\\tNTLM V2\\r\\n\\tKey Length:\\t\\t0\\r\\n\\r\\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\\r\\n\\r\\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\\r\\n\\r\\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\\r\\n\\r\\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\\r\\n\\r\\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\\r\\n\\r\\nThe authentication information fields provide detailed information about this specific logon request.\\r\\n\\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\\r\\n\\t- Transited services indicate which intermediate services have participated in this logon request.\\r\\n\\t- Package name indicates which sub-protocol was used among the NTLM protocols.\\r\\n\\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\",\"RecordNumber\":214981812,\"SourceName\":\"Microsoft-Windows-Security-Auditing\",\"TimeGenerated\":\"20160727210240.818850-000\",\"TimeWritten\":\"20160727210240.818850-000\",\"Type\":\"Audit Success\",\"User\":\"\",\"Host\":\"10.14.56.249\"}");
		System.out.println("An account was successfully logged on.\\r\\n\\r\\nSubject:\\r\\n\\tSecurity ID:\\t\\tS-1-0-0\\r\\n\\tAccount Name:\\t\\t-\\r\\n\\tAccount Domain:\\t\\t-\\r\\n\\tLogon ID:\\t\\t0x0\\r\\n\\r\\nLogon Type:\\t\\t\\t3\\r\\n\\r\\nNew Logon:\\r\\n\\tSecurity ID:\\t\\tS-1-5-21-99512129-1830164216-1097030630-547334\\r\\n\\tAccount Name:\\t\\tKED578\\r\\n\\tAccount Domain:\\t\\tCOF\\r\\n\\tLogon ID:\\t\\t0x2c9fa027\\r\\n\\tLogon GUID:\\t\\t{00000000-0000-0000-0000-000000000000}\\r\\n\\r\\nProcess Information:\\r\\n\\tProcess ID:\\t\\t0x0\\r\\n\\tProcess Name:\\t\\t-\\r\\n\\r\\nNetwork Information:\\r\\n\\tWorkstation Name:\\tCUSATX165226\\r\\n\\tSource Network Address:\\t10.218.217.133\\r\\n\\tSource Port:\\t\\t6169\\r\\n\\r\\nDetailed Authentication Information:\\r\\n\\tLogon Process:\\t\\tNtLmSsp \\r\\n\\tAuthentication Package:\\tNTLM\\r\\n\\tTransited Services:\\t-\\r\\n\\tPackage Name (NTLM only):\\tNTLM V2\\r\\n\\tKey Length:\\t\\t0\\r\\n\\r\\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\\r\\n\\r\\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\\r\\n\\r\\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\\r\\n\\r\\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\\r\\n\\r\\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\\r\\n\\r\\nThe authentication information fields provide detailed information about this specific logon request.\\r\\n\\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\\r\\n\\t- Transited services indicate which intermediate services have participated in this logon request.\\r\\n\\t- Package name indicates which sub-protocol was used among the NTLM protocols.\\r\\n\\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.");
	}
}
