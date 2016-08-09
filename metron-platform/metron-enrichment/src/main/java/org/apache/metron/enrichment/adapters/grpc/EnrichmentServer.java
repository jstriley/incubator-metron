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

import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;
import org.apache.metron.enrichment.adapters.grpc.generated.EnrichGrpc;
import org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply;
import org.apache.metron.enrichment.adapters.grpc.generated.EnrichRequest;

import java.io.IOException;
import java.util.logging.Logger;

/**
 * A GRPC server class that takes in messages and
 * serves an enrichment value
 */
public class EnrichmentServer {

  private static final Logger logger = Logger.getLogger(EnrichmentServer.class.getName());

  private int port = 50051;
  private Server server;

  /**
   * Starts the server on the current machine,
   * listening on the specified port
   */
  protected void start() throws IOException {
    server = ServerBuilder.forPort(port)
      .addService(new EnrichImpl())
      .build()
      .start();
    logger.info("Server started, listening on port " + port);
    Runtime.getRuntime().addShutdownHook(new Thread() {
      @Override
      public void run() {
        System.err.println("*** shutting down gRPC server since JVM is shutting down");
        EnrichmentServer.this.stop();
        System.err.println("*** server shut down");
      }
    });
  }

  protected void stop() {
    if (server!=null) {
      server.shutdown();
    }
  }

  protected void blockUntilShutdown() throws InterruptedException {
    if (server!=null) {
      server.awaitTermination();
    }
  }

  //Launch the server from the command line
  public static void main(String[] args) throws IOException, InterruptedException {
    final EnrichmentServer server = new EnrichmentServer();
    server.start();
    server.blockUntilShutdown();
  }

  /**
   * A private class that extends the proto-generated base class
   * in order to implement the enrich method to take in a request
   * and provide a response
   */
  private class EnrichImpl extends EnrichGrpc.EnrichImplBase {

    public void enrich(EnrichRequest request, StreamObserver<EnrichReply> responseObserver) {

      // Do what you want with the features
      int featureCount = request.getFeaturesCount();
      EnrichReply reply = EnrichReply.getDefaultInstance();

      for (int i=0; i<featureCount; i++) {
        logger.info("Dealing with feature: " + request.getFeatures(i));
        reply = EnrichReply.newBuilder().setScore(2.4).build();
      }

      responseObserver.onNext(reply);
      responseObserver.onCompleted();

      logger.info("Scoring the features on the server!");

    }

  }

}
