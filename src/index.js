const { ApolloServer } = require('apollo-server');
const typeDefs = require('./schema');
const resolvers = require('./resolvers.js');
const DigTraceAPI = require('./datasources/dig-trace');
const SonarAPI = require('./datasources/sonar-api');
const SonarWebcheck = require('./datasources/webcheck')
const TcpCheck = require('./datasources/tcpcheck')
const PropigationCheck = require('./datasources/propigationcheck');
const DnsLookup = require('./datasources/dnslookup');

const server = new ApolloServer({
    typeDefs,
    resolvers,
    dataSources: () => ({
        digTraceAPI: new DigTraceAPI(),
        sonarAPI: new SonarAPI(),
        sonarWebcheck: new SonarWebcheck(),
        tcpCheck: new TcpCheck(),
        propigationCheck: new PropigationCheck(),
        dnsLookup: new DnsLookup()
    }),
});

server.listen().then(({ url }) => {
    console.log(`🚀 Server ready at ${url}`);
});
