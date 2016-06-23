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

package org.apache.metron.common.writer;

import backtype.storm.task.OutputCollector;
import backtype.storm.tuple.Tuple;
import com.google.common.collect.Iterables;
import org.apache.metron.common.Constants;
import org.apache.metron.common.configuration.writer.WriterConfiguration;
import org.apache.metron.common.interfaces.BulkMessageWriter;
import org.apache.metron.common.utils.ErrorUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.Map.Entry;

public class BulkWriterComponent<MESSAGE_T> {
  public static final Logger LOG = LoggerFactory
          .getLogger(BulkWriterComponent.class);
  private Map<String, Collection<Tuple>> sensorTupleMap = new HashMap<>();
  private OutputCollector collector;
  private boolean handleCommit = true;
  private boolean handleError = true;
  private Long currentTime;
  private Long flushIntervalInMs;
  private boolean flush;
  private long totalESWaitTime=0;
  private long lastESRun=0;
  private int currentBatchSize=0;

  public BulkWriterComponent(OutputCollector collector) {
    this.collector = collector;
    this.currentTime = System.currentTimeMillis();
    this.flush = false;
  }

  public BulkWriterComponent(OutputCollector collector, boolean handleCommit, boolean handleError) {
    this(collector);
    this.handleCommit = handleCommit;
    this.handleError = handleError;
    this.currentTime = System.currentTimeMillis();
    this.flush = false;
  }

  public void setFlush(boolean flush) {
    LOG.info("Setting flush to " + flush);
    this.flush = flush;
  }

  public void setFlushIntervalInMs(Long flushIntervalInMs) {
    LOG.info("Setting flushIntervalInMs to " + flushIntervalInMs);
    this.flushIntervalInMs = flushIntervalInMs;
  }

  public void commit(Iterable<Tuple> tuples) {
    tuples.forEach(t -> collector.ack(t));
    if(LOG.isDebugEnabled()) {
      LOG.debug("Acking " + Iterables.size(tuples) + " tuples");
    }
  }

  public void error(Throwable e, Iterable<Tuple> tuples) {
    tuples.forEach(t -> collector.ack(t));
    if(!Iterables.isEmpty(tuples)) {
      LOG.error("Failing " + Iterables.size(tuples) + " tuples", e);
      ErrorUtils.handleError(collector, e, Constants.ERROR_STREAM);
    }
  }

  protected Collection<Tuple> createTupleCollection() {
    return new ArrayList<>();
  }


  public void errorAll(Throwable e) {
    for(Map.Entry<String, Collection<Tuple>> kv : sensorTupleMap.entrySet()) {
      error(e, kv.getValue());
      sensorTupleMap.remove(kv.getKey());
      //sensorMessageMap.remove(kv.getKey());
    }
  }

  public void errorAll(String sensorType, Throwable e) {
    error(e, Optional.ofNullable(sensorTupleMap.get(sensorType)).orElse(new ArrayList<>()));
    sensorTupleMap.remove(sensorType);
    //  sensorMessageMap.remove(sensorType);
  }
  public void write( String sensorType
          , Tuple tuple
          , MESSAGE_T message
          , BulkMessageWriter<MESSAGE_T> bulkMessageWriter
          , WriterConfiguration configurations
  ) throws Exception
  {

    int batchSize;
    currentBatchSize++;

    if(configurations.getGlobalConfig().get(Constants.GLOBAL_BATCH_SIZE)!=null)
      batchSize= Integer.parseInt(configurations.getGlobalConfig().get(Constants.GLOBAL_BATCH_SIZE).toString());
    else
      batchSize=configurations.getBatchSize(sensorType);

    Collection<Tuple> tupleList = sensorTupleMap.get(sensorType);
    if (tupleList == null) {
      tupleList = createTupleCollection();
    }
    tupleList.add(tuple);
//    List<MESSAGE_T> messageList = sensorMessageMap.get(sensorType);
//    if (messageList == null) {
//      messageList = new ArrayList<>();
//    }

    if(configurations.getGlobalConfig()!=null&&configurations.getGlobalConfig().get(Constants.FLUSH_FLAG)!=null)
    {
      this.setFlush(Boolean.getBoolean(configurations.getGlobalConfig().get(Constants.FLUSH_FLAG).toString()));
      if(configurations.getGlobalConfig().get(Constants.FLUSH_INTERVAL_IN_MS)!=null)
      {
        this.setFlushIntervalInMs(Long.parseLong(configurations.getGlobalConfig().get(Constants.FLUSH_INTERVAL_IN_MS).toString()));
        LOG.trace("Setting time based flushing FLUSH_INTERVAL_IN_MS to "+configurations.getGlobalConfig().get(Constants.FLUSH_INTERVAL_IN_MS).toString());
      }
    }
    //  messageList.add(message);
    if ((flush && (System.currentTimeMillis() >= currentTime + flushIntervalInMs))) {
      flushAllSensorTypes(bulkMessageWriter, configurations);
      LOG.trace("Flushing due to timeout. flushIntervalInMs"+flushIntervalInMs);
    } else if ((currentBatchSize >= batchSize)) {
      flushAllSensorTypes(bulkMessageWriter, configurations);
      currentBatchSize=0;
      //sensorTupleMap.remove(sensorType);
    } else {
      sensorTupleMap.put(sensorType, tupleList);
      //  sensorMessageMap.put(sensorType, messageList);
    }
  }

  private void flushAllSensorTypes (BulkMessageWriter<MESSAGE_T> bulkMessageWriter, WriterConfiguration configurations) throws Exception {
    Iterator<Entry<String, Collection<Tuple>>> iterator=sensorTupleMap.entrySet().iterator();

    String sensrorType = null;
    while (iterator.hasNext()) {
      try {
        sensrorType=iterator.next().getKey();
        if(flush(bulkMessageWriter, configurations, sensorTupleMap)){
          iterator.remove();
          LOG.debug("Flushing tuples for sensrorType:"+sensrorType+" tuples:"+sensorTupleMap.get(sensrorType).size());
        }
      } catch (Exception e) {
        LOG.warn("Exception thrown while flushing senson type " + sensrorType, e);
        LOG.warn("Continuing with next sensor type");
      }
    }
    if (flush) {
      currentTime = System.currentTimeMillis();
    }
  }

  private boolean flush(BulkMessageWriter<MESSAGE_T> bulkMessageWriter, WriterConfiguration configurations,
                        Map<String, Collection<Tuple>> sensorTupleMap2) throws Exception {

    boolean flushed=false;
    try {
      lastESRun=System.currentTimeMillis();
      bulkMessageWriter.write(configurations, sensorTupleMap);
      LOG.debug("ES flush time:"+(System.currentTimeMillis()-lastESRun));
      totalESWaitTime=totalESWaitTime+System.currentTimeMillis()-lastESRun;
      LOG.debug("ES total flush time:"+totalESWaitTime );

      flushed=true;
      if(handleCommit) {
        Iterator<Entry<String, Collection<Tuple>>> iterator=sensorTupleMap.entrySet().iterator();
        while(iterator.hasNext()){
          commit(sensorTupleMap.get(iterator.next().getKey()));
        }
      }
    } catch (Throwable e) {

      if(handleError) {
        Iterator<Entry<String, Collection<Tuple>>> iterator=sensorTupleMap.entrySet().iterator();
        while(iterator.hasNext()){
          error(e, sensorTupleMap.get(iterator.next().getKey()));
        }

      }
      else {
        //Doing nothing if handleError flag is off
        LOG.error("Doing nothing if handleError flag is off");
      }
    }
    finally {
      Iterator<Entry<String, Collection<Tuple>>> iterator=sensorTupleMap.entrySet().iterator();
      while(iterator.hasNext()){
        sensorTupleMap.get(iterator.next().getKey()).clear();
      }
    }
    return flushed;

  }

  private boolean flush(String sensorType, BulkMessageWriter<MESSAGE_T> bulkMessageWriter, WriterConfiguration configurations, Collection<Tuple> tupleList,
                        List<MESSAGE_T> messageList ) throws Exception {
    boolean flushed=false;
    try {
      lastESRun=System.currentTimeMillis();
      bulkMessageWriter.write(configurations, sensorTupleMap);
      LOG.debug("ES flush time:"+(System.currentTimeMillis()-lastESRun));
      totalESWaitTime=totalESWaitTime+System.currentTimeMillis()-lastESRun;
      LOG.debug("ES total flush time:"+totalESWaitTime );

      flushed=true;
      if(handleCommit) {
        commit(tupleList);
      }
    } catch (Throwable e) {

      if(handleError) {
        error(e, tupleList);
      }
      else {
        throw e;
      }
    }
    finally {
      // sensorMessageMap.remove(sensorType);
    }
    return flushed;
  }
}
