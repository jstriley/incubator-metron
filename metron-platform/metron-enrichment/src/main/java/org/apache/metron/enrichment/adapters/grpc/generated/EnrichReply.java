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

// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: enrichment.proto

package org.apache.metron.enrichment.adapters.grpc.generated;

/**
 * Protobuf type {@code grpc.EnrichReply}
 */
public  final class EnrichReply extends
    com.google.protobuf.GeneratedMessage implements
    // @@protoc_insertion_point(message_implements:grpc.EnrichReply)
    EnrichReplyOrBuilder {
  // Use EnrichReply.newBuilder() to construct.
  private EnrichReply(com.google.protobuf.GeneratedMessage.Builder<?> builder) {
    super(builder);
  }
  private EnrichReply() {
    score_ = 0D;
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return com.google.protobuf.UnknownFieldSet.getDefaultInstance();
  }
  private EnrichReply(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    this();
    int mutable_bitField0_ = 0;
    try {
      boolean done = false;
      while (!done) {
        int tag = input.readTag();
        switch (tag) {
          case 0:
            done = true;
            break;
          default: {
            if (!input.skipField(tag)) {
              done = true;
            }
            break;
          }
          case 9: {

            score_ = input.readDouble();
            break;
          }
        }
      }
    } catch (com.google.protobuf.InvalidProtocolBufferException e) {
      throw e.setUnfinishedMessage(this);
    } catch (java.io.IOException e) {
      throw new com.google.protobuf.InvalidProtocolBufferException(
          e).setUnfinishedMessage(this);
    } finally {
      makeExtensionsImmutable();
    }
  }
  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return org.apache.metron.enrichment.adapters.grpc.generated.GrpcEnrichment.internal_static_grpc_EnrichReply_descriptor;
  }

  protected com.google.protobuf.GeneratedMessage.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return org.apache.metron.enrichment.adapters.grpc.generated.GrpcEnrichment.internal_static_grpc_EnrichReply_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply.class, org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply.Builder.class);
  }

  public static final int SCORE_FIELD_NUMBER = 1;
  private double score_;
  /**
   * <code>optional double score = 1;</code>
   */
  public double getScore() {
    return score_;
  }

  private byte memoizedIsInitialized = -1;
  public final boolean isInitialized() {
    byte isInitialized = memoizedIsInitialized;
    if (isInitialized == 1) return true;
    if (isInitialized == 0) return false;

    memoizedIsInitialized = 1;
    return true;
  }

  public void writeTo(com.google.protobuf.CodedOutputStream output)
                      throws java.io.IOException {
    if (score_ != 0D) {
      output.writeDouble(1, score_);
    }
  }

  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (score_ != 0D) {
      size += com.google.protobuf.CodedOutputStream
        .computeDoubleSize(1, score_);
    }
    memoizedSize = size;
    return size;
  }

  private static final long serialVersionUID = 0L;
  public static org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessage
        .parseWithIOException(PARSER, input);
  }
  public static org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessage
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessage
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessage
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessage
        .parseWithIOException(PARSER, input);
  }
  public static org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply parseFrom(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessage
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public Builder newBuilderForType() { return newBuilder(); }
  public static Builder newBuilder() {
    return DEFAULT_INSTANCE.toBuilder();
  }
  public static Builder newBuilder(org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply prototype) {
    return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
  }
  public Builder toBuilder() {
    return this == DEFAULT_INSTANCE
        ? new Builder() : new Builder().mergeFrom(this);
  }

  @java.lang.Override
  protected Builder newBuilderForType(
      com.google.protobuf.GeneratedMessage.BuilderParent parent) {
    Builder builder = new Builder(parent);
    return builder;
  }
  /**
   * Protobuf type {@code grpc.EnrichReply}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessage.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:grpc.EnrichReply)
      org.apache.metron.enrichment.adapters.grpc.generated.EnrichReplyOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return org.apache.metron.enrichment.adapters.grpc.generated.GrpcEnrichment.internal_static_grpc_EnrichReply_descriptor;
    }

    protected com.google.protobuf.GeneratedMessage.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return org.apache.metron.enrichment.adapters.grpc.generated.GrpcEnrichment.internal_static_grpc_EnrichReply_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply.class, org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply.Builder.class);
    }

    // Construct using org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply.newBuilder()
    private Builder() {
      maybeForceBuilderInitialization();
    }

    private Builder(
        com.google.protobuf.GeneratedMessage.BuilderParent parent) {
      super(parent);
      maybeForceBuilderInitialization();
    }
    private void maybeForceBuilderInitialization() {
      if (com.google.protobuf.GeneratedMessage.alwaysUseFieldBuilders) {
      }
    }
    public Builder clear() {
      super.clear();
      score_ = 0D;

      return this;
    }

    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return org.apache.metron.enrichment.adapters.grpc.generated.GrpcEnrichment.internal_static_grpc_EnrichReply_descriptor;
    }

    public org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply getDefaultInstanceForType() {
      return org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply.getDefaultInstance();
    }

    public org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply build() {
      org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    public org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply buildPartial() {
      org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply result = new org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply(this);
      result.score_ = score_;
      onBuilt();
      return result;
    }

    public Builder mergeFrom(com.google.protobuf.Message other) {
      if (other instanceof org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply) {
        return mergeFrom((org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply other) {
      if (other == org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply.getDefaultInstance()) return this;
      if (other.getScore() != 0D) {
        setScore(other.getScore());
      }
      onChanged();
      return this;
    }

    public final boolean isInitialized() {
      return true;
    }

    public Builder mergeFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }

    private double score_ ;
    /**
     * <code>optional double score = 1;</code>
     */
    public double getScore() {
      return score_;
    }
    /**
     * <code>optional double score = 1;</code>
     */
    public Builder setScore(double value) {
      
      score_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional double score = 1;</code>
     */
    public Builder clearScore() {
      
      score_ = 0D;
      onChanged();
      return this;
    }
    public final Builder setUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return this;
    }

    public final Builder mergeUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return this;
    }


    // @@protoc_insertion_point(builder_scope:grpc.EnrichReply)
  }

  // @@protoc_insertion_point(class_scope:grpc.EnrichReply)
  private static final org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply();
  }

  public static org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<EnrichReply>
      PARSER = new com.google.protobuf.AbstractParser<EnrichReply>() {
    public EnrichReply parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
        return new EnrichReply(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<EnrichReply> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<EnrichReply> getParserForType() {
    return PARSER;
  }

  public org.apache.metron.enrichment.adapters.grpc.generated.EnrichReply getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}
