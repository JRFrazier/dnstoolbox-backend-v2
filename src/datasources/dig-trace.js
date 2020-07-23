const { RESTDataSource } = require('apollo-datasource-rest');

class DigTraceAPI extends RESTDataSource {
    constructor() {
        super();
        this.baseURL = 'http://sonarliteremote1.constellix.com'
    }

    async digTrace(host) {
        const response = await this.get(`/dig/trace/${host}`)
        return response
    }



}

module.exports = DigTraceAPI