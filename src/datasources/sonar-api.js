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

class SonarAPI extends RESTDataSource {
    constructor() {
        super();
        this.baseURL = 'https://api.sonar.constellix.com/rest/';
    }
    willSendRequest(request) {
        request.headers.set('x-cns-security-token', token());
    }

    async traceroute(hostname, location, protocol, ipVersion) {
        const response = await this.get(`checks/traceroute/${location}/${hostname}/${ipVersion}?protocol=${protocol}`);
        return response;
    }

    async dnsLookup(location, hostname, nameserver, recordType) {
        const response = await this.get(`dig/${location}/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });
        return response;
    }
}

module.exports = SonarAPI;
