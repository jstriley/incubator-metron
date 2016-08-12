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

package org.apache.metron.enrichment.adapters.grpc;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.StatusRuntimeException;
import org.apache.metron.enrichment.adapters.grpc.generated.EnrichGrpc;

import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A GRPC client to be used in the enrichment adapter
 */
public class EnrichmentClient {

  private static final Logger logger = Logger.getLogger(EnrichmentClient.class.getName());

  private final ManagedChannel channel;
  private final EnrichGrpc.EnrichBlockingStub blockingStub;

  /**
   * @param host - the address of the server that the client will reach out to
   * @param port - the port that the server will be listening on
   */
  public EnrichmentClient(String host, int port) {
    channel = ManagedChannelBuilder.forAddress(host, port)
      .usePlaintext(true)
      .build();
    blockingStub = EnrichGrpc.newBlockingStub(channel);
    logger.info("Constructed EnrichmentClient for " + host + ":" + port);
  }

  public void shutdown() throws InterruptedException {
    channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
  }

  /**
   * Request the score from the enrichment server
   *
   * @param feature - the value to send to the server for enrichment
   * @return the score returned by the enrichment server
   */
  public double getEnrichment(String feature) {
    double score = 0;
    logger.info("Trying to request score for the feature: " + feature);

    //Create a Feature object that can be a double or a String to send to the model server
    org.apache.metron.enrichment.adapters.grpc.generated.Feature featureObject =
      org.apache.metron.enrichment.adapters.grpc.generated.Feature.newBuilder().setStringFeature(feature).build();

    //Use the Feature to create a request that will be sent to the enrichment server
    org.apache.metron.enrichment.adapters.grpc.generated.EnrichRequest request =
      org.apache.metron.enrichment.adapters.grpc.generated.EnrichRequest.newBuilder()
        .addFeatures(featureObject).build();

    //Try to contact the server and get a response, our score for the enrichment
    org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply response;
    try {
      logger.info("Contacting server");
      response = blockingStub.enrich(request);
      score = response.getScore();
      logger.info("Server returned score: " + score);
    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    }
    logger.info("Score: " + score);
    return score;
  }

  /**
   * A main method for testing purposes
   */
  public static void main(String[] args) throws Exception {
    EnrichmentClient client = new EnrichmentClient("localhost", 50051);
    try {
      String feature = "www.test.com";
      if (args.length > 0) {
        feature = args[0];
        System.out.println("Help!");
      }
      client.getEnrichment(feature);
    } finally {
      client.shutdown();
    }
  }

}
