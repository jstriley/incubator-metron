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
  private Map<String, List<MESSAGE_T>> sensorMessageMap = new HashMap<>();
  private OutputCollector collector;
  private boolean handleCommit = true;
  private boolean handleError = true;
  private Long lastFlushTime;
  private Long flushIntervalInMs;
  private boolean flush;
  private long totalESWaitTime=0;
  private long lastESRun=0;
  private int currentBatchSize=0;
  private boolean indexError=false;

  public BulkWriterComponent(OutputCollector collector) {
    this.collector = collector;
    this.lastFlushTime = System.currentTimeMillis();
    this.flush = false;
  }

  public BulkWriterComponent(OutputCollector collector, boolean handleCommit, boolean handleError) {
    this(collector);
    this.handleCommit = handleCommit;
    this.handleError = handleError;
    this.lastFlushTime = System.currentTimeMillis();
    this.flush = false;
  }

  public void setFlush(boolean flush) {
    this.flush = flush;
  }

  public void setFlushIntervalInMs(Long flushIntervalInMs) {
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


      if(indexError){
        ErrorUtils.handleError(collector, e, Constants.ERROR_STREAM);
      }

    }
  }

  protected Collection<Tuple> createTupleCollection() {
    return new ArrayList<>();
  }


  public void errorAll(Throwable e) {
    for(Map.Entry<String, Collection<Tuple>> kv : sensorTupleMap.entrySet()) {
      error(e, kv.getValue());
      sensorTupleMap.remove(kv.getKey());
      sensorMessageMap.remove(kv.getKey());
    }
  }

  public void errorAll(String sensorType, Throwable e) {
    error(e, Optional.ofNullable(sensorTupleMap.get(sensorType)).orElse(new ArrayList<>()));
    sensorTupleMap.remove(sensorType);
    sensorMessageMap.remove(sensorType);
  }
  public void write( String sensorType, Tuple tuple, MESSAGE_T message, BulkMessageWriter<MESSAGE_T> bulkMessageWriter, WriterConfiguration configurations) throws Exception
  {

    int batchSize = configurations.getBatchSize(sensorType);
    Collection<Tuple> tupleList = sensorTupleMap.get(sensorType);
    if (tupleList == null) {
      tupleList = createTupleCollection();
    }
    tupleList.add(tuple);
    List<MESSAGE_T> messageList = sensorMessageMap.get(sensorType);
    if (messageList == null) {
      messageList = new ArrayList<>();
    }
    messageList.add(message);
    if (tupleList.size() >= batchSize) {
      flush(sensorType, bulkMessageWriter, configurations, tupleList, messageList);
    } else {
      sensorTupleMap.put(sensorType, tupleList);
      sensorMessageMap.put(sensorType, messageList);
    }
  }

  private void flushAllSensorTypes (BulkMessageWriter<MESSAGE_T> bulkMessageWriter, WriterConfiguration configurations) throws Exception {

    try {
      lastESRun=System.currentTimeMillis();
      bulkMessageWriter.write(configurations, sensorTupleMap,collector );
      LOG.debug("ES flush time:"+(System.currentTimeMillis()-lastESRun));
      totalESWaitTime=totalESWaitTime+System.currentTimeMillis()-lastESRun;
      LOG.debug("ES total flush time:"+totalESWaitTime );
      LOG.trace("Flushed "+currentBatchSize+" tuples for all sensors:");

      if(handleCommit) {
        Iterator<Entry<String, Collection<Tuple>>> iterator=sensorTupleMap.entrySet().iterator();
        while(iterator.hasNext()){
          commit(iterator.next().getValue());
        }
      }
    }catch (Throwable e) {
      LOG.debug("Ex:ES flush time:"+(System.currentTimeMillis()-lastESRun));
      LOG.debug("Ex:ES total flush time:"+totalESWaitTime );
      LOG.trace("Ex:Flushed "+currentBatchSize+" tuples for all sensors:");

      if(configurations.getGlobalConfig()!=null&&configurations.getGlobalConfig().get(Constants.ERROR_INDEX_FLAG)!=null){
        indexError=Boolean.parseBoolean(configurations.getGlobalConfig().get(Constants.ERROR_INDEX_FLAG).toString());
        LOG.trace("ERROR_INDEX_FLAG: "+indexError);
      }

      if(handleError) {
        Iterator<Entry<String, Collection<Tuple>>> iterator=sensorTupleMap.entrySet().iterator();
        while(iterator.hasNext()){
          error(e, iterator.next().getValue());
        }
      }
      else {
        throw e;
      }
    }
    finally {

      sensorTupleMap.clear();
      currentBatchSize = 0;
    }
    if (flush) {
      lastFlushTime = System.currentTimeMillis();
    }
  }



  private boolean flush(String sensorType, BulkMessageWriter<MESSAGE_T> bulkMessageWriter, WriterConfiguration configurations, Collection<Tuple> tupleList,
                        List<MESSAGE_T> messageList ) throws Exception {
    boolean flushed=false;
    try {
      lastESRun=System.currentTimeMillis();
      bulkMessageWriter.write(sensorType, configurations, tupleList, messageList);
      LOG.debug("ES flush time "+(System.currentTimeMillis()-lastESRun));
      totalESWaitTime=totalESWaitTime+System.currentTimeMillis()-lastESRun;
      LOG.debug("ES total flush time "+totalESWaitTime );

      flushed=true;
      if(handleCommit) {
        commit(tupleList);
      }
    } catch (Throwable e) {

      if(handleError) {
        if(configurations.getGlobalConfig()!=null&&configurations.getGlobalConfig().get(Constants.ERROR_INDEX_FLAG)!=null){
          indexError=Boolean.parseBoolean(configurations.getGlobalConfig().get(Constants.ERROR_INDEX_FLAG).toString());
          LOG.trace("ERROR_INDEX_FLAG: "+indexError);
        }
        error(e, tupleList);
      }
      else {
        throw e;
      }
    }
    finally {
      sensorTupleMap.remove(sensorType);
      sensorMessageMap.remove(sensorType);
    }
    return flushed;
  }

  public void write(String sensorType,Tuple tuple
          , BulkMessageWriter<MESSAGE_T> bulkMessageWriter
          , WriterConfiguration configurations) throws Exception {
    int batchSize;
    currentBatchSize++;

    try{
      batchSize = Integer.parseInt(configurations.getGlobalConfig().get(Constants.GLOBAL_BATCH_SIZE).toString());
    }catch (Exception e){
      throw new Exception("Set globalBatchSize in zookeeper global.json");
    }


    Collection<Tuple> tupleList = sensorTupleMap.get(sensorType);
    if (tupleList == null)
    {
      tupleList = createTupleCollection();
    }
    tupleList.add(tuple);
    sensorTupleMap.put(sensorType, tupleList);

    if(configurations.getGlobalConfig()!=null&&configurations.getGlobalConfig().get(Constants.FLUSH_FLAG)!=null)
    {
      this.setFlush(Boolean.parseBoolean(configurations.getGlobalConfig().get(Constants.FLUSH_FLAG).toString()));
      if (configurations.getGlobalConfig().get(Constants.FLUSH_INTERVAL_IN_MS) != null)
      {
        this.setFlushIntervalInMs(Long.parseLong(configurations.getGlobalConfig().get(Constants.FLUSH_INTERVAL_IN_MS).toString()));
        LOG.trace("Setting time based flushing  to " +configurations.getGlobalConfig().get(Constants.FLUSH_FLAG)+" with timeout of"+ configurations.getGlobalConfig().get(Constants.FLUSH_INTERVAL_IN_MS).toString());
      }
    }

    if (currentBatchSize >= batchSize || (flush && (System.currentTimeMillis() >= (lastFlushTime + flushIntervalInMs)))){
      try {
        flushAllSensorTypes(bulkMessageWriter, configurations);
        LOG.trace("GlobalBatchSize: "+batchSize);
      } catch (Exception e) {
        LOG.error("Exception while flushing all messages: " + e.getMessage()+" Sensor Type "+sensorType+" currentBatchSize " +currentBatchSize);
        throw e;
      }
    }


  }

}


