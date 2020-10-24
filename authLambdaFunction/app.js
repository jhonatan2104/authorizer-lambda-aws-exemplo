const jwt = require('jsonwebtoken');

exports.lambdaHandler = (event, context, callback) => {
  console.log("Client token: " + event.authorizationToken);
  var token = event.authorizationToken;
  if(!token) {
    callback("Unauthorized");
  } else {
    jwt.verify(token, process.env.SECRET, function(error, decoded) {
      if(error) {
        callback(null, generatePolicy("user", "Deny", event.methodArn));
      } else {
        callback(null, generatePolicy("user", "Allow", event.methodArn));
      }
    })
  }
};

var generatePolicy = (principalId, effect, resource) => {
  var authResponse = {};

  authResponse.principalId = principalId;

  if (effect && resource) {
    var statementOne = {
      Action: "execute-api:Invoke",
      Effect: effect,
      Resource: resource,
    };

    var policyDocument = {
      Version: "2012-10-17",
      Statement: [statementOne],
    };

    authResponse.policyDocument = policyDocument;
  }

  authResponse.context = {
    stringKey: "stringval",
    numberKey: 123,
    booleanKey: true,
  };

  return authResponse;
};
