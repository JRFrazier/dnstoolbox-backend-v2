const { gql } = require('apollo-server');

const typeDefs = gql`
    type Query {
        traceroute(hostname: String!, location: String!, protocol: String!, ipVersion: String!): Traceroute!
        digTrace(host: String!): DigTrace!,
        dnsLookup(location: String!, hostname: String!, nameserver: String!, recordType: String! ): Dig!, 
        webCheck(location: String!, hostname: String!, ipVersion: String!, protocol: String!, port: Int!): WebCheck!,
        tcpCheck(location: String!, hostname: String!, ipVersion: String!, port: Int!): TcpCheck!
        propigationCheck(location: String!, hostname: String!, nameserver: String!, recordType: String! ): PropigationCheck!, 

    }
    type Traceroute {
        result: String!
    }
    type DigTrace {
        result: String!
    }
    type Dig {
        host: String!
        responsetime: Int!
        recordtype: String!
        checkedat: String!
        location: String!
        result: [String!]
    }
    type WebCheck {
        status: String!
        responsetime: Int!
        resolvedip: String! 
    }
    type TcpCheck {
        status: String!
        responsetime: Int!
        resolvedip: String! 
    }
 
    type PropigationCheck {
        uswas: [String]
        cator: [String] 
        usfmt: [String] 
        defra: [String] 
        jptyo: [String] 
        hkhkg: [String] 
        nlams: [String] 
        uschi: [String] 
        usdal: [String] 
        inmaa: [String] 
        ussjc: [String] 
        usnyc: [String] 
        auadl: [String] 
        gblon: [String] 
        usatl: [String] 
        cobog: [String] 
        itmil: [String] 
        dkcph: [String] 
        inblr: [String] 
        frpar: [String] 
        sgsin: [String] 
        ausyd: [String] 
        clscl: [String] 
        brsao: [String] 
        nzakl: [String] 
        ussea: [String] 
        ussfo: [String] 
        usewr: [String] 
        uslax: [String] 
        usmia: [String] 
        atvie: [String] 
    }
`;

module.exports = typeDefs;