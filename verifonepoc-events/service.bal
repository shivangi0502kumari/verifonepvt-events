import ballerinax/trigger.asgardeo;
import ballerina/log;
import ballerina/http;
import ballerina/cache;
import ballerina/time;
import ballerina/regex;
import ballerina/lang.array;

configurable asgardeo:ListenerConfig config = ?;

listener http:Listener httpListener = new (8090);
listener asgardeo:Listener webhookListener = new (config, httpListener);

cache:Cache cache = new ({
    evictionFactor: 0.2,
    defaultMaxAge: 3600,
    cleanupInterval: 60
});

configurable string ASGARDEO_HOST = "https://api.asgardeo.io/t/verifonepvt";
configurable string ENTITY_ID_CLAIM = "http://wso2.org/claims/entityID";
configurable string ENTITY_SERVICE_ENDPOINT = "https://dev.portal.test-gsc.vfims.com/oidc/ds-entity-service/entities/";
configurable string[] WESTPAC_ENTITY_IDS = ["a1b4d79b-c5ed-4573-8380-611b18e7a2f4", "52b59912-4ae7-466b-beaf-a5f92f4f3f50", "c63e1d33-88f8-4198-bb8b-c52554e0f0d3", "7cd21095-a0cb-4819-bdbf-71535652fb72"];
configurable string CLIENT_ID_CC_GRANT_ENTITY_SERVICE = "ud2QuZWMntKhLRfVbPhDtp0PMn4a";
configurable string CLIENT_SECRET_CC_GRANT_ENTITY_SERVICE = "";
configurable string SCOPES_CC_GRANT_ENTITY_SERVICE = "";
configurable string VERIFONE_DOMAIN = "verifone.com";
configurable string MESSAGING_SERVICE_ENDPOINT = "https://dev.portal.test-gsc.vfims.com/oidc/vfmessaging/";
configurable string MESSAGING_SERVICE_SUB_PATH = "messages/send";
configurable string CLIENT_ID_CC_GRANT_MESSAGING_SERVICE = "ud2QuZWMntKhLRfVbPhDtp0PMn4a";
configurable string CLIENT_SECRET_CC_GRANT_MESSAGING_SERVICE = "";
configurable string SCOPES_CC_GRANT_MESSAGING_SERVICE = "";
configurable string FIRST_NAME_CLAIM = "http://wso2.org/claims/givenname";
configurable string LAST_NAME_CLAIM = "http://wso2.org/claims/lastname";
configurable string PARENT_ENTITY_ID_VALUE = "";

service asgardeo:RegistrationService on webhookListener {

    remote function onAddUser(asgardeo:AddUserEvent event) returns error? {

        log:printInfo("on add user : " + event.toString());
        json eventReceived = event.toJson();
        string userid = check eventReceived.eventData.userId;
        log:printInfo("User Id : " + userid);
        map<string> claims = check (check eventReceived.eventData.claims).cloneWithType();
        log:printInfo("Claims received : " + claims.toString());

        string entityID = check claims[ENTITY_ID_CLAIM].ensureType();
        log:printInfo("entity ID received : " + entityID);

        string firstName = check claims[FIRST_NAME_CLAIM].ensureType();
        log:printInfo("First Name : " + firstName);

        string lastName = check claims[LAST_NAME_CLAIM].ensureType();
        log:printInfo("Last Name : " + lastName);

        string userName = check eventReceived.eventData.userName;
        log:printInfo("username : " + userName);

        string emailDomain = extractDomain(userName);
        log:printInfo("Email Domain : " + emailDomain);

        string parentEntityID = "";
        json responseData = {};
        string federationStatus = "false";

        if (entityID != PARENT_ENTITY_ID_VALUE) {
            log:printInfo("Entity ID is equal to the configured parent entity id");
            parentEntityID = (check responseData.parentEntityUid).toString();
            responseData = retrieveEntityServiceInformation(entityID);
            federationStatus = (check responseData.federationStatus).toString();

            log:printInfo("parent entity id : " + parentEntityID);
            log:printInfo("federation status : " + federationStatus);
        }

        if (responseData is ()) {
            log:printError("Error occurred while fetching entity service info");
        }

        json payload = {};

        if ((emailDomain == VERIFONE_DOMAIN && federationStatus == "false")) {
            log:printInfo("domain matched to verifone domain.");
            payload = {
                "eventData": {
                    "source": "welcomeEmail",
                    "content": {
                        "FIRST_NAME": firstName,
                        "URL": "//www.verifone.com/en/us",
                        "CURRENT_YEAR": extractCurrentYear().toString()
                    }
                },
                "messages": {
                    "email": [
                        {
                            "to": {
                                "email": userName
                            }
                        }
                    ]
                }
            };

            invokeMessagingService(payload);

        } else if (federationStatus == "true") {
            log:printInfo("fedederaiton status is true. Hence skipping calling the messaging service.");
        } else if (array:indexOf(WESTPAC_ENTITY_IDS, parentEntityID) >= 0) {
            log:printInfo("parent entity id equals to the configured westpac entity id ");
            payload = {
                "eventData": {
                    "source": "welcomeEmail",
                    "content": {
                        "FIRST_NAME": firstName,
                        "LAST_NAME": lastName,
                        "USERNAME": userName,
                        "senderEntityUid": entityID
                    }
                },
                "messages": {
                    "email": [
                        {
                            "to": {
                                "email": userName
                            }
                        }
                    ]
                }
            };
            invokeMessagingService(payload);

        } else {
            log:printInfo(" not matching for any condition. UserName: " + userName + "- Entity ID : " + entityID + "- federationStatus : " + federationStatus);
            payload = {
                "eventData": {
                    "source": "welcomeEmail",
                    "content": {
                        "FIRST_NAME": firstName,
                        "URL": "//www.verifone.com/en/us",
                        "CURRENT_YEAR": extractCurrentYear().toString()
                    }
                },
                "messages": {
                    "email": [
                        {
                            "to": {
                                "email": userName
                            }
                        }
                    ]
                }
            };

            invokeMessagingService(payload);
        }
    }

    remote function onConfirmSelfSignup(asgardeo:GenericEvent event) returns error? {

        log:printInfo(event.toJsonString());
    }

    remote function onAcceptUserInvite(asgardeo:GenericEvent event) returns error? {

        log:printInfo(event.toJsonString());
    }
}

service /ignore on httpListener {
}

function generateClientCredentialsToken(string scopes, string client_Id, string client_secret) returns string|error? {

    if (isTokenActive(client_Id)) {
        string accessTokenFromCache = check cache.get(string:concat(client_Id, "_accessToken")).ensureType(string);
        log:printInfo("Access token is active. Getting from the cache : " + accessTokenFromCache);
        return accessTokenFromCache;
    }

    http:ClientConfiguration httpClientConfig = {
        httpVersion: "1.1",
        timeout: 20
    };
    http:Client|http:ClientError? httpClient = new (ASGARDEO_HOST, httpClientConfig);

    if (httpClient is http:Client) {
        string requestBody = "grant_type=client_credentials&client_id=".concat(client_Id, "&client_secret=", client_secret, "&scope=", scopes);

        http:Response|http:ClientError tokenResponse = check httpClient->post("/oauth2/token", requestBody, {"Content-Type": "application/x-www-form-urlencoded"});

        if (tokenResponse is http:Response) {
            json tokenResponseJson = check tokenResponse.getJsonPayload();
            log:printInfo("Token response: " + tokenResponseJson.toString());

            string accessToken = check tokenResponseJson.access_token.ensureType();
            log:printInfo("Access token: " + accessToken + " for client id : " + client_Id);
            int expires_in = check tokenResponseJson.expires_in.ensureType();
            log:printInfo("Token expiry time: " + expires_in.toString());

            check cache.put(string:concat(client_Id, "_accessToken"), accessToken.toString());
            check cache.put(string:concat(client_Id, "_tokenExpiryTime"), expires_in.toString());
            check cache.put(string:concat(client_Id, "_tokenGeneratedTime"), time:utcNow().toString());

            return accessToken;
        } else {
            log:printError("Error occurred while generating the token: " + tokenResponse.toString());
        }
        return ();
    }

}

function isTokenActive(string clientid) returns boolean {

    string currentTime = time:utcNow().toString();
    log:printInfo("Current time: " + currentTime);

    if (cache.hasKey(string:concat(clientid, "_tokenGeneratedTime")) == true && cache.hasKey(string:concat(clientid, "_tokenExpiryTime")) == true) {
        log:printInfo("Access token information is in the cache");
        string tokenGeneratedTime = "";
        var generatedTime = cache.get(string:concat(clientid, "_tokenGeneratedTime")).ensureType(string);
        if (generatedTime is string) {
            tokenGeneratedTime = generatedTime;
        } else {
            log:printError("Error retrieving token generated time from cache: " + generatedTime.toString());
            return false;
        }
        log:printInfo("Token generated time: " + tokenGeneratedTime);

        string tokenExpiryTime = "";
        var expiryTime = cache.get(string:concat(clientid, "_tokenExpiryTime")).ensureType(string);
        if (expiryTime is string) {
            tokenExpiryTime = expiryTime;
        } else {
            log:printError("Error retrieving token expiry time from cache: " + expiryTime.toString());
            return false;
        }
        log:printInfo("Token expiry time: " + tokenExpiryTime);

        int|error? tokenExpiryTimeResult = int:fromString(tokenExpiryTime);

        if (tokenExpiryTimeResult is int && getCurrentTimeInMilliSeconds(currentTime) - getGeneratedTimeInMilliSeconds(tokenGeneratedTime) > tokenExpiryTimeResult) {
            log:printInfo("Access token expired. Generating a new token");
            return false;
        } else {
            log:printInfo("Access token is still valid. Reusing the existing token");
            return true;
        }

    } else {
        log:printInfo("Access token information is not in the cache. Generating a new token");
        return false;
    }
}

function getCurrentTimeInMilliSeconds(string currentTime) returns int {

    string currentTimeStr = currentTime.toString().substring(1, currentTime.toString().length() - 1);
    string[] currentTimeArr = regex:split(currentTimeStr, ",");

    int|error currentTimeInMilliSeconds = int:fromString(currentTimeArr[0].toString());

    if (currentTimeInMilliSeconds is error) {
        log:printInfo("Error while converting the string to int : " + currentTimeInMilliSeconds.toString());
    } else {
        log:printInfo("Current time in milliseconds: " + currentTimeInMilliSeconds.toString());
        return currentTimeInMilliSeconds;
    }
    return 0;
}

function getGeneratedTimeInMilliSeconds(string generatedTime) returns int {

    string generatedTimeStr = generatedTime.toString().substring(1, generatedTime.toString().length() - 1);
    string[] generatedTimeArr = regex:split(generatedTimeStr, ",");

    int|error generatedTimeInMilliSeconds = int:fromString(generatedTimeArr[0].toString());

    if (generatedTimeInMilliSeconds is error) {
        log:printInfo("Error while converting the string to int : " + generatedTimeInMilliSeconds.toString());
    } else {
        log:printInfo("Generated time in milliseconds: " + generatedTimeInMilliSeconds.toString());
        return generatedTimeInMilliSeconds;
    }
    return 0;
}

function retrieveEntityServiceInformation(string entityID) returns json {
    http:ClientConfiguration httpClientConfig = {
        httpVersion: "1.1",
        timeout: 20
    };

    http:Client|http:ClientError httpEndpoint = new (ENTITY_SERVICE_ENDPOINT, httpClientConfig);
    string|error? accessToken = generateClientCredentialsToken(SCOPES_CC_GRANT_ENTITY_SERVICE, CLIENT_ID_CC_GRANT_ENTITY_SERVICE, CLIENT_SECRET_CC_GRANT_ENTITY_SERVICE);

    if (httpEndpoint is error) {
        log:printInfo("Error while creating connection with entity service endpoint : " + httpEndpoint.toString());
    } else {
        if (accessToken is string) {
            map<string> headers = {
                "content-type": "application/json",
                "Authorization": "Bearer " + (accessToken).toString()
            };
            http:Response|http:ClientError entityServiceResponse = httpEndpoint->get(entityID, headers);
            if (entityServiceResponse is http:Response) {
                int postResponseStatusCode = entityServiceResponse.statusCode;
                json|error entityServiceResponseData = entityServiceResponse.getJsonPayload();
                if (entityServiceResponseData is json) {
                    log:printInfo("Entity Service Response: " + entityServiceResponseData.toString());
                    if (postResponseStatusCode != 200) {
                        log:printError("Error occurred while fetching entity sevice data. Status Code: " + postResponseStatusCode.toString());
                        return ();
                    }
                    return entityServiceResponseData;
                } else {
                    log:printError("Error occurred while parsing entity Service Data: " + entityServiceResponseData.toString());
                }

            } else {
                log:printError("Error occurred while fetching entity service response: " + entityServiceResponse.toString());
            }

        } else {
            log:printError("Error occurred while generating the access token.");
        }
    }

}

function extractDomain(string email) returns string {
    string[] parts = regex:split(email, "@");
    if parts.length() == 2 {
        return parts[1];
    } else {
        return "";
    }
}

function invokeMessagingService(json payload) {

    log:printInfo("payload : " + payload.toString());

    http:ClientConfiguration httpClientConfig = {
        httpVersion: "1.1",
        timeout: 20
    };

    http:Client|http:ClientError httpEndpoint = new (MESSAGING_SERVICE_ENDPOINT, httpClientConfig);
    string|error? accessToken = generateClientCredentialsToken(SCOPES_CC_GRANT_MESSAGING_SERVICE, CLIENT_ID_CC_GRANT_MESSAGING_SERVICE, CLIENT_SECRET_CC_GRANT_MESSAGING_SERVICE);

    if (httpEndpoint is error) {
        log:printInfo("Error while creating connection with messaging service endpoint : " + httpEndpoint.toString());
    } else {
        if (accessToken is string) {
            map<string> headers = {
                "content-type": "application/json",
                "Authorization": "Bearer " + (accessToken).toString()
            };
            http:Response|http:ClientError messagingServiceResponse = httpEndpoint->post(MESSAGING_SERVICE_SUB_PATH, payload, headers);
            if (messagingServiceResponse is http:Response) {
                int postResponseStatusCode = messagingServiceResponse.statusCode;
                json|error messagingServiceResponseData = messagingServiceResponse.getJsonPayload();
                if (postResponseStatusCode != 200) {
                    log:printError("Error occurred while fetching messaging sevice data. Status Code: " + postResponseStatusCode.toString());
                    return ();
                } else {
                    if (messagingServiceResponseData is json) {
                        log:printInfo("Message sent successfully. " + messagingServiceResponseData.toString());
                    } else {
                        log:printInfo("Messaging service response data is not in json format.");
                    }
                }

            } else {
                log:printError("Error occurred while fetching entity service response: " + messagingServiceResponse.toString());
            }

        } else {
            log:printError("Error occurred while generating the access token.");
        }
    }
}

function extractCurrentYear() returns int {
    time:Utc currentUtcTime = time:utcNow();
    time:Civil currentCivilTime = time:utcToCivil(currentUtcTime);
    int currentYear = currentCivilTime.year;
    log:printInfo("Current Year: " + currentYear.toString());
    return currentYear;
}
