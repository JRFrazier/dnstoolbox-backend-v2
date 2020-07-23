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

class PropigationCheck extends RESTDataSource {
    constructor() {
        super();
        this.baseURL = 'https://sonar.constellix.com/rest/';
    }
    willSendRequest(request) {
        request.headers.set('x-cns-security-token', token());
    }


    async propigationCheck(location, hostname, nameserver, recordType) {
        const washingtonDc = await this.get(`dig/uswas01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const torontoCA = await this.get(`dig/cator01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const fremontCa = await this.get(`dig/usfmt01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const defra = await this.get(`dig/defra01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const jptyo = await this.get(`dig/jptyo01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const hkhkg = await this.get(`dig/hkhkg01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const nlams = await this.get(`dig/nlams01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const uschi = await this.get(`dig/uschi01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const usdal = await this.get(`dig/usdal01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const inmaa = await this.get(`dig/inmaa01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const ussjc = await this.get(`dig/ussjc01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const usnyc = await this.get(`dig/usnyc01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const auadl = await this.get(`dig/auadl01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const gblon = await this.get(`dig/gblon01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const usatl = await this.get(`dig/usatl01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const cobog = await this.get(`dig/cobog01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const itmil = await this.get(`dig/itmil01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const dkcph = await this.get(`dig/dkcph01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const inblr = await this.get(`dig/inblr01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const frpar = await this.get(`dig/frpar01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const sgsin = await this.get(`dig/sgsin01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const clscl = await this.get(`dig/clscl01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const brsao = await this.get(`dig/brsao01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const nzakl = await this.get(`dig/nzakl01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const ussea = await this.get(`dig/ussea01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const ussfo = await this.get(`dig/ussfo01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const usewr = await this.get(`dig/usewr01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const uslax = await this.get(`dig/uslax01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const usmia = await this.get(`dig/usmia01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });

        const atvie = await this.get(`dig/atvie01-mon01.nodes.constellix.net/${nameserver}/${hostname}?recordtype=${recordType} `, {
            hostname: `${hostname}`,
            nameServer: `${nameserver}`,
            recordType: `${recordType}`,
            expectedIp: '',
        });



        const obj =
        {
            "uswas": washingtonDc.result,
            "cator": torontoCA.result,
            "usfmt": fremontCa.result,
            "defra": defra.result,
            "jptyo": jptyo.result,
            "hkhkg": hkhkg.result,
            "nlams": nlams.result,
            "uschi": uschi.result,
            "usdal": usdal.result,
            "inmaa": inmaa.result,
            "ussjc": ussjc.result,
            "usnyc": usnyc.result,
            "auadl": auadl.result,
            "gblon": gblon.result,
            "usatl": usatl.result,
            "cobog": cobog.result,
            "itmil": itmil.result,
            "dkcph": dkcph.result,
            "inblr": inblr.result,
            "frpar": frpar.result,
            "sgsin": sgsin.result,
            "clscl": clscl.result,
            "brsao": brsao.result,
            "nzakl": nzakl.result,
            "ussea": ussea.result,
            "ussfo": ussfo.result,
            "usewr": usewr.result,
            "uslax": uslax.result,
            "usmia": usmia.result,
            "atvie": atvie.result,
        }

        return obj


    }
}

module.exports = PropigationCheck;