package com.accantosystems.stratoss.vnfmdriver.model.alm;

import java.io.IOException;
import java.util.*;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

public class ExecutionRequestPropertyValueDeserializer extends StdDeserializer<ExecutionRequestPropertyValue> {

    private static final long serialVersionUID = 2L;

    public ExecutionRequestPropertyValueDeserializer() {
        super(ExecutionRequestPropertyValue.class);
    }

    @Override
    public ExecutionRequestPropertyValue deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        ObjectMapper mapper = (ObjectMapper) jp.getCodec();
        if (mapper == null) {
            mapper = new ObjectMapper();
        }

        JsonNode root = mapper.readTree(jp);
        String type = getFieldValueAsString(root, "type");
        if (Objects.equals(type, PropertyType.KEY.getValue())) {
            return mapper.treeToValue(root, KeyExecutionRequestPropertyValue.class);
        } else {
            return mapper.treeToValue(root, GenericExecutionRequestPropertyValue.class);
        }
    }

    private String getFieldValueAsString(JsonNode node, String fieldName) {
        return node.has(fieldName) ? node.get(fieldName).asText() : null;
    }
}
