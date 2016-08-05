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

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.metron.parsers.BasicParser;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("serial")
public class BasicRedsealParser extends BasicParser {

    private static final Logger _LOG = LoggerFactory.getLogger(BasicRedsealParser.class);
    private SimpleDateFormat df = new SimpleDateFormat("MMM dd yyyy HH:mm:ss");

    @Override
    public void configure(Map<String, Object> parserConfig) {

    }

    @Override
    public void init() {

    }

    @SuppressWarnings({ "unchecked", "unused" })
    public List<JSONObject> parse(byte[] msg) {

        String message = "";
        List<JSONObject> messages = new ArrayList<>();
        JSONObject payload = new JSONObject();

        try {
            message = new String(msg, "UTF-8");

            payload.put("original_string", message);
            String[] parts = message.split("<|>|\\(|\\)|\\[|\'| ");
            payload.put("priority", parts[1]);

            int year = Calendar.getInstance().get(Calendar.YEAR);
            Date date = df.parse(parts[2] + " " + parts[3] + " " + year + " "+ parts[4]);
            long epoch = date.getTime();

            payload.put("timestamp", epoch);

            payload.put("hostname", parts[5]);
            String syslog = parts[6].replace(":", ""); //remove colon from end of syslog_facility name
            payload.put("syslog_facility", syslog);

            if(message.contains("DeviceProduct") || message.contains("LastSeenDate"))
            {   //redseal event log
                payload.put("log:type", "redseal-event");
                String eventLog[] = message.split(" - ");
                //eventLog[1] = eventLog[1].replace(" ","");
                String logPairs[] = eventLog[1].split(" \\| ");
                for(int i = 0; i < logPairs.length-1; i++)
                {
                    String pair[] = logPairs[i].split("=");
                    payload.put(pair[0],pair[1]);
                }
            }
            else if(syslog.equals("local0"))
            {   //redseal server log
                payload.put("log:type", "redseal-server");
                payload.put("message", message.split("local0: ")[1]);
            }
            else if(syslog.equals("local1"))
            {   //redseal analysis
                payload.put("log:type", "redseal-analysis");
                payload.put("message", message.split("local1: ")[1]);
            }
            else if(syslog.equals("local2"))
            {   //one of 5 audit types
                payload.put("log:type", "redseal-audit");
                String auditMessage = message.split("local2: ")[1];
                auditMessage = auditMessage.replace("]","'");
                String log[] = auditMessage.split("\\[|\'");

                if(message.contains("user authenticated OK"))
                {   //audit1 and 2
                    payload.put("authentication_result", "success");
                    payload.put("username", log[1].replace(" ",""));
                    payload.put("ip_src_addr", log[3].replace(" ",""));
                    if(message.contains("/"))  //audit1
                    {
                        String audit1[] = log[2].split(" ");
                        payload.put("protocol", audit1[1]);
                        payload.put("uri_path", audit1[9]);
                    }
                }
                else if(message.contains("user connection authenticated"))
                {   //audit3
                    payload.put("authentication_result", "success");
                    payload.put("username", log[2]);
                    String audit3[] = log[1].split(" ");
                    payload.put("protocol", audit3[1]);
                }
                else if(message.contains("user authentication FAILED"))
                {   //audit4
                    payload.put("authentication_result", "failure");
                    payload.put("username", log[1].replace(" ", ""));
                    payload.put("ip_src_addr", log[3].replace(" ",""));
                }
                else
                {   //audit5
                    payload.put("username", log[1].replace(" ", ""));
                    payload.put("message", log[2].substring(1,log[2].length()));
                }
            }
            else if(syslog.equals("local3"))
            {   //redseal system log
                payload.put("log:type", "redseal-system");
                payload.put("message", message.split("local3: ")[1]);
            }

            messages.add(payload);
            return messages;

        } catch (Exception e) {
            e.printStackTrace();
            _LOG.error("Failed to parse: " + message);
            return null;
        }
    }

}

