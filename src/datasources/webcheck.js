const { RESTDataSource } = require('apollo-datasource-rest');

const hmacSHA1 = require('crypto-js/hmac-sha1');
const Base64 = require('crypto-js/enc-base64');

const apiKey = "5762d9c3-403e-4233-bc53-ff56b89d3c2e"
const secretKey = "295093d8-439d-4dfa-bb68-4996a6ed8574"

function epochTime() {
    return new Date().getTime() + '';
}

function token() {
    const time = epochTime()
    const hmac = hmacSHA1(time, secretKey).toString(Base64);
    const token = apiKey + ":" + hmac + ":" + time;
    return token
}

class SonarWebcheck extends RESTDataSource {
    constructor() {
        super();
        this.baseURL = 'https://sonar.constellix.com/rest/checks/';
    }
    willSendRequest(request) {
        request.headers.set('x-cns-security-token', token());
    }

    async webCheck(location, hostname, ipVersion, protocol, port) {
        const response = await this.post(`test/${location}`,
            {
                "protocolTypes": `${protocol}`, "interval": "ONEMINUTE", "ipversion": `${ipVersion}`, "port": `${port}`, "ip": `${hostname}`, "expectedStatusCode": "200"
            }
        )
        return response
    }
}

module.exports = SonarWebcheck;
