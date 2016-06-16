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

package org.apache.metron.parsers.mcafeeepo;


import org.apache.metron.parsers.BasicParser;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

public class BasicMcAfeeEpoParser extends BasicParser {
    private static final Logger LOGGER = LoggerFactory.getLogger(BasicMcAfeeEpoParser.class);
    private SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

    @Override
    public void init() {
    }

    @Override
    public void configure(Map<String, Object> config) {
    }

    @SuppressWarnings({ "unchecked", "unused" })
    public List<JSONObject> parse(byte[] msg) throws Exception {
        df.setTimeZone(TimeZone.getTimeZone("UTC"));

        String message = "";
        List<JSONObject> messages = new ArrayList<>();
        JSONObject payload = new JSONObject();

        try {
            message = new String(msg, "UTF-8");

            String[] parts = message.split("<|>|\", |\" |\"$");
            if(parts.length < 2){
                LOGGER.error("Failed to parse: " + message);
                throw new Exception("Unable to parse message: " + message);
            }
            payload.put("original_string", message);
            payload.put("priority", parts[1]);

            String timestamp = "";
            for(int i = 3; i < parts.length; i++){
                String[] keypair = parts[i].split("=\"");
                if(keypair.length != 2){
                    LOGGER.error("Failed to parse: " + message);
                    throw new Exception("Unable to parse message: " + message);
                }
                if(keypair[0].equals("src_ip"))
                    keypair[0] = "ip_src_addr";
                if(keypair[0].equals("dest_ip"))
                    keypair[0] = "ip_dst_addr";

                if(keypair[0].equals("timestamp")){
                    timestamp = keypair[1];

                } else if(!keypair[1].equals("NULL") && !keypair[1].equals("_")){
                    payload.put(keypair[0], keypair[1]);
                }
            }

            //No standard way to go between the timezone field value and a timezone, so they have to be done manually
            String timezone = (String)payload.get("timezone");
            if(timezone != null){
                df.setTimeZone(TimeZone.getTimeZone("GMT"));
            }

            int missingZeros = "yyyy-MM-dd HH:mm:ss.SSS".length() - timestamp.length();
            timestamp += new String(new char[missingZeros]).replace("\0", "0"); // add on the missing zeros
            payload.put("timestamp", df.parse(timestamp).getTime());

            messages.add(payload);
            if (null == messages || messages.isEmpty()) {
                throw new Exception("Unable to parse McAfee Epo data: " + message);
            }
            return messages;
        } catch (Exception e) {
            LOGGER.error("Failed to parse: " + message, e);
            throw e;
        }
    }


}
