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


import org.apache.metron.parsers.BasicParser;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BasicPaloAltoFirewallParser extends BasicParser {

    private String dateFormatString;
    private TimeZone timeZone;

    private static final Logger LOGGER = LoggerFactory.getLogger
            (BasicPaloAltoFirewallParser.class);

    private static final long serialVersionUID = 3147090149725343999L;
    private static final String[] TRAFFIC_FIELDS = {
            "receive_time",
            "serial_number",
            "type",
            "subtype",
            "future_use2",
            "generated_time",
            "ip_src_addr",
            "ip_dst_addr",
            "nat_source_ip",
            "nat_destination_ip",
            "rule_name",
            "src_user_name",
            "dst_user_name",
            "application",
            "virtual_system",
            "source_zone",
            "destination_zone",
            "ingress_interface",
            "egress_interface",
            "log_forwarding_profile",
            "future_use3",
            "session_id",
            "repeat_count",
            "ip_src_port",
            "ip_dst_port",
            "nat_source_port",
            "nat_destination_port",
            "flags",
            "protocol",
            "action",
            "bytes",
            "bytes_sent",
            "bytes_received",
            "packets",
            "start_time",
            "elapsed_time",
            "category",
            "future_use4",
            "sequence_number",
            "action_flags",
            "source_location",
            "destination_location",
            "future_use5",
            "packets_sent",
            "packets_received",
            "session_end_reason",
            "device_group_hierarchy_level1",
            "device_group_hierarchy_level2",
            "device_group_hierarchy_level3",
            "device_group_hierarchy_level4",
            "virtual_system_name",
            "device_name",
            "action_source"};

    private static final String[] THREAT_FIELDS = {
            "receive_time",
            "serial_number",
            "type",
            "subtype",
            "future_use2",
            "generated_time",
            "ip_src_addr",
            "ip_dst_addr",
            "nat_source_ip",
            "nat_destination_ip",
            "rule_name",
            "src_user_name",
            "dst_user_name",
            "application",
            "virtual_system",
            "source_zone",
            "destination_zone",
            "ingress_interface",
            "egress_interface",
            "log_forwarding_profile",
            "future_use3",
            "session_id",
            "repeat_count",
            "ip_src_port",
            "ip_dst_port",
            "nat_source_port",
            "nat_destination_port",
            "flags",
            "protocol",
            "action",
            "miscellaneous",
            "threat_id",
            "category",
            "severity",
            "direction",
            "sequence_number",
            "action_flags",
            "source_location",
            "destination_location",
            "future_use4",
            "content_type",
            "pcap_id",
            "file_digest",
            "cloud",
            "url_index",
            "user_agent",
            "file_type",
            "x_forwarded_for",
            "referrer",
            "sender",
            "subject",
            "recipient",
            "report_id",
            "device_group_hierarchy_level1",
            "device_group_hierarchy_level2",
            "device_group_hierarchy_level3",
            "device_group_hierarchy_level4",
            "virtual_system_name",
            "device_name",
            "future_use5",
            "future_use6"};

    private static final String[] CONFIG_FIELDS = {
            "receive_time",
            "serial_number",
            "type",
            "subtype",
            "future_use2",
            "generated_time",
            "host",
            "virtual_system",
            "command",
            "admin",
            "client",
            "result",
            "configuration_path",
            "sequence_number",
            "action_flags",
            "device_group_hierarchy_level1",
            "device_group_hierarchy_level2",
            "device_group_hierarchy_level3",
            "device_group_hierarchy_level4",
            "virtual_system_name",
            "device_name"};

    private static final String[] SYSTEM_FIELDS = {
            "receive_time",
            "serial_number",
            "type",
            "subtype",
            "future_use2",
            "generated_time",
            "virtual_system",
            "event_id",
            "object",
            "future_use3",
            "future_use4",
            "module",
            "severity",
            "description",
            "sequence_number",
            "action_flags",
            "device_group_hierarchy_level1",
            "device_group_hierarchy_level2",
            "device_group_hierarchy_level3",
            "device_group_hierarchy_level4",
            "virtual_system_name",
            "device_name"};


    @Override
    public void init() {

    }

    @SuppressWarnings({"unchecked", "unused"})
    public List<JSONObject> parse(byte[] msg) {
        JSONObject outputMessage = new JSONObject();
        String toParse = new String(msg);
        List<JSONObject> messages = new ArrayList<>();
        try {
            LOGGER.debug("Received message: " + toParse);

            parseMessage(toParse, outputMessage);

            outputMessage.put("original_string", toParse);
            messages.add(outputMessage);
            return messages;
        } catch (Exception e) {
            LOGGER.error("Failed to parse: " + toParse, e);
            throw new IllegalStateException("Unable to Parse Message: " + toParse + " due to " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private void parseMessage(String message, JSONObject outputMessage) {

        ArrayList<String> tokens = new ArrayList<>(Arrays.asList(message.split(",")));
        String lastValue = message.substring(message.lastIndexOf(",")+1);
        if (lastValue == "")
            tokens.add(lastValue);
        //populate common objects
        parseFirstField(tokens.get(0), outputMessage);

        String type = tokens.get(3).trim();
        switch(type) {
            case "TRAFFIC": parseTuple(tokens, outputMessage, TRAFFIC_FIELDS);
                break;
            case "THREAT":  parseTuple(tokens, outputMessage, THREAT_FIELDS);
                break;
            case "CONFIG":  parseTuple(tokens, outputMessage, CONFIG_FIELDS);
                break;
            case "SYSTEM":  parseTuple(tokens, outputMessage, SYSTEM_FIELDS);
                break;
        }
    }

    private void parseTuple(ArrayList<String> tokens, JSONObject outputMessage, String[] fields) {
        int numFields = fields.length;
        int numTokens = tokens.size() - 1;
        int count;
        for(count = 0; count < numTokens; count++){
            outputMessage.put(fields[count],tokens.get(count+1));
        }

        for(; count < numFields; count++)
            outputMessage.put(fields[count],"");
        removeEmptyFields(outputMessage);
    }

    private void parseFirstField(String firstField, JSONObject outputMessage) {
        //split first field by empty space
        String[] tokens = firstField.split("\\s+");
        //get priority inside of < >
        Pattern pattern = Pattern.compile("<.*>");
        Matcher matcher = pattern.matcher(tokens[0]);
        //add priority
        if(matcher.find())
        {
            String priorityNum = matcher.group(0);
            outputMessage.put("priority", priorityNum.substring(1, priorityNum.length()-1));
        }
        //add timestamp
        String tempDate = tokens[0].substring(tokens[0].indexOf(">") +1) + " " + tokens[1] + " " + tokens[2];
        outputMessage.put("timestamp", this.formatTimestamp(tempDate));

        //add hostname
        outputMessage.put("hostname", tokens[3]);
        //add future use
        outputMessage.put("future_use", tokens[4]);
    }

    protected long formatTimestamp(Object value) {
        long epochTimestamp = System.currentTimeMillis();
        if (value != null) {
            try {
                epochTimestamp = toEpoch(Calendar.getInstance().get(Calendar.YEAR)  + " " + value);
            } catch (java.text.ParseException e) {
                //default to current time
            }
        }
        return epochTimestamp;
    }

    protected long toEpoch(String datetime) throws java.text.ParseException {

        SimpleDateFormat dateFormat = new SimpleDateFormat(dateFormatString);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Parser converting timestamp to epoch: " + datetime);
        }

        dateFormat.setTimeZone(timeZone);
        Date date = dateFormat.parse(datetime);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Parser converted timestamp to epoch: " + date);
        }

        return date.getTime();
    }

    @SuppressWarnings("unchecked")
    private void removeEmptyFields(JSONObject json) {
        Iterator<Object> keyIter = json.keySet().iterator();
        while (keyIter.hasNext()) {
            Object key = keyIter.next();
            Object value = json.get(key);
            if (null == value || "".equals(value.toString())) {
                keyIter.remove();
            }
        }
    }

    //For specifying the date format that the parser will use
   public BasicPaloAltoFirewallParser withDateFormat(String dateFormat) {
     if (dateFormat == null) {
       throw new IllegalArgumentException("DateFormat must be specified in parser config file");
     }
     this.dateFormatString = dateFormat;
      if (LOG.isDebugEnabled()) {
       LOG.debug("Palo Alto parser setting date format: " + dateFormat);
      }
     return this;
    }

    //For setting the timezone of the parser
    public BasicPaloAltoFirewallParser withTimeZone(String timeZone) {
      if (timeZone == null) {
        timeZone = "UTC";
      }
      this.timeZone = TimeZone.getTimeZone(timeZone);
      if (LOG.isDebugEnabled()) {
        LOG.debug("CEF parser setting timezone: " + timeZone);
      }
      return this;
    }

    @Override
    public void configure(Map<String, Object> config) {
      withDateFormat((String) config.get("dateFormat"));
      withTimeZone((String) config.get("timeZone"));
    }

}
