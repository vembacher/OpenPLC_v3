//
// Created by v on 08.10.21.
//
#include "spdlog/spdlog.h"

#include <string>
#include "opc_ua_server.h"

extern "C" {
#include "open62541/server_config_default.h"
}

#include "common.h"
#include "glue.h"
#include "nodes.h"

#include <csignal>
#include <cstdlib>
#include <mutex>


UA_Server *get_ua_server_with_encryption(const GlueVariablesBinding &binding, const char *config)
{
    //NOTE: currently the paths are hard-coded, the structure is based on how UaExpert stores certificates.
    //      a future goal will be that this is configurable and more convenient.

    spdlog::debug("OPC UA server: Loading PKI related files.");
    auto certificate = loadFile("../etc/PKI/own/certs/plc.cert.der");
    auto privateKey = loadFile("../etc/PKI/own/private/plc.key.der");
    auto trusted_root_ca = loadFile("../etc/PKI/trusted/certs/ca.cert.der");
    auto trusted_intermediate_ca = loadFile("../etc/PKI/trusted/certs/ca-chain.cert.der");
    auto ua_expert = loadFile("../etc/PKI/trusted/certs/uaexpert.der");
    auto trusted = (ua_expert.length) ?
                   (std::vector<UA_ByteString>{trusted_root_ca, trusted_intermediate_ca, ua_expert}) :
                   (std::vector<UA_ByteString>{trusted_root_ca, trusted_intermediate_ca});

    // We need a CRL for every CA, otherwise certificates signed by this CA will NOT be accepted.
    UA_STACKARRAY(UA_ByteString, revocation_list, 2);
    revocation_list[0] = loadFile("../etc/PKI/trusted/crl/ca.crl.pem");
    revocation_list[1] = loadFile("../etc/PKI/trusted/crl/intermediate.crl.pem");

//    std::vector<UA_ByteString> trusted = load_files_in_dir("/etc/openplc/PKI/trusted/certs");
//    std::vector<UA_ByteString> crls = load_files_in_dir("/etc/openplc/PKI/trusted/crl");

    //TODO: handle issuers
    UA_ByteString *issuers = nullptr;

    auto server = UA_Server_new();
    spdlog::debug("OPC UA server: Setting server config.");
    auto server_config = UA_Server_getConfig(server);
    auto retval = UA_ServerConfig_setDefaultWithSecurityPolicies(
            server_config,          // *conf,
            4840,         // portNumber,
            &certificate,           // *certificate,
            &privateKey,            // *privateKey,
            trusted.data(),         // *trustList,
            trusted.size(),         // trustListSize,
            issuers,                // *issuerList,
            0,           // issuerListSize,
            revocation_list,        // *revocationList,
            2         // revocationListSize
    );

    if (retval != UA_STATUSCODE_GOOD)
    {
        spdlog::error("OPC UA server: Error adding default config.");

        if (certificate.length == 0)
        {
            spdlog::error("OPC UA server: Could not load certificate.");
        }
        if (privateKey.length == 0)
        {
            spdlog::error("OPC UA server: Could not load private key.");
            std::cerr << "Could not load private key\n";
        }
        if (not ua_expert.length)
        {
            spdlog::error("OPC UA server: could not load UaExpert cert as trusted cert.");
        }
        if (not trusted_root_ca.length)
        {
            spdlog::error("OPC UA server: could not load trusted root cert.");
        }
        if (not trusted_intermediate_ca.length)
        {
            spdlog::error("OPC UA server: could not load trusted intermediate cert.");
        }
        exit(0);
    }
    spdlog::debug("OPC UA server: Cleaning up filedescriptors.");
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    for (auto p: trusted)
    { UA_ByteString_clear(&p); }
    for (auto p: revocation_list) { UA_ByteString_clear(&p); }
    return server;
}


void oplc::opcua_server::opc_ua_service_run(const GlueVariablesBinding &binding,
                                            volatile bool &run, const char *config)
{


    auto server = get_ua_server_with_encryption(binding, config);

    spdlog::debug("OPC UA server: Adding program related nodes.");
    auto context_store = add_nodes_to_server(server, binding);
    spdlog::debug("OPC UA server: Running server.");
    auto retval = UA_Server_run(server, &run);

    //TODO: delete context_store items safely
    // reference: https://stackoverflow.com/questions/16527673/c-one-stdvector-containing-template-class-of-multiple-types
    spdlog::debug("OPC UA server: Stopping server.");
    UA_Server_delete(server);

};