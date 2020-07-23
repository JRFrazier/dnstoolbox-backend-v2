module.exports = {
    Query: {
        traceroute: (_, { hostname, location, protocol, ipVersion }, { dataSources }) =>
            dataSources.sonarAPI.traceroute(hostname, location, protocol, ipVersion),

        digTrace: (_, { host }, { dataSources }) => dataSources.digTraceAPI.digTrace(host),

        dnsLookup: (_, { location, hostname, nameserver, recordType }, { dataSources }) =>
            dataSources.dnsLookup.dnsLookup(location, hostname, nameserver, recordType),

        webCheck: (_, { location, hostname, ipVersion, protocol, port }, { dataSources }) => dataSources.sonarWebcheck.webCheck(location, hostname, ipVersion, protocol, port),

        tcpCheck: (_, { location, hostname, ipVersion, port }, { dataSources }) => dataSources.tcpCheck.tcpCheck(location, hostname, ipVersion, port),

        propigationCheck: (_, { location, hostname, nameserver, recordType }, { dataSources }) =>
            dataSources.propigationCheck.propigationCheck(location, hostname, nameserver, recordType),

    },
};
