/*
 This is the generic message creation logic for ScaleVnfRequest messages based on the 2.4.1 version of the ETSI SOL003 specification
 */
logger.debug('Generating ScaleVnfRequest message for ETSI SOL003 v2.4.1');
load('classpath:scripts/lib.js');

// Create the message object to be returned
var message = {additionalParams: {}};

// Set the standard message properties
message.type = executionRequest.properties.scaleType;
message.aspectId = executionRequest.properties.scaleAspectId;
setPropertyIfNotNull(executionRequest.properties, message, 'numberOfSteps');

for (var key in executionRequest.getProperties()) {
    if (key.startsWith('additionalParams.')) {
        // print('Got property [' + key + '], value = [' + executionRequest.properties[key] + ']');
        addProperty(message, key, executionRequest.properties[key]);
    }
}

logger.debug('Message generated successfully');
// Turn the message object into a JSON string to be returned back to the Java driver
JSON.stringify(message);