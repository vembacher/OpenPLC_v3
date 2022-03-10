#include <cstdlib>
#include <mbedtls/x509_crt.h>

#include "spdlog/spdlog.h"
#include "opc_ua_server.h"
#include "common.h"
#include "glue.h"
#include "nodes.h"
#include "opc_ua_utils.h"
#include "server_config.h"


UA_Server *get_ua_server_with_encryption(const GlueVariablesBinding &binding, const oplc::OpcUaServerConfig &config)
{

    spdlog::debug("OPC UA server: creating server with encryption.");

    spdlog::debug("OPC UA server: Loading PKI related files.");
    auto certificate = loadFile(config.server_cert_path.data());
    auto private_key = loadFile(config.server_pkey_path.data());

    std::vector<UA_ByteString> trusted;
    for (const auto &path: config.trust_list_paths)
    {
        auto file = loadFile(path.data());
        if (file.length == 0)
        {
            spdlog::error("OPC UA server: could not load trusted certificate with path: {}", path);
            continue;
        }
        trusted.push_back(file);
    }

    // We need a CRL for every CA, otherwise certificates signed by this CA will NOT be accepted.
    std::vector<UA_ByteString> revocation_list;
    for (const auto &path: config.revocation_list_paths)
    {
        auto file = loadFile(path.data());
        if (file.length == 0)
        {
            spdlog::error("OPC UA server: could not load CRL with path: {}", path);
            continue;
        }
        revocation_list.push_back(file);
    }



    //TODO: handle issuers, using CAs as trusted certificates works
    std::vector<UA_ByteString> issuers;
    for (const auto &path: config.issuers_paths)
    {
        auto file = loadFile(path.data());
        if (file.length == 0)
        {
            spdlog::error("OPC UA server: could not load issuer certificate with path: {}", path);
            continue;
        }
        issuers.push_back(file);
    }

    auto server = oplc::opcua_server::UA_Server_new();
    spdlog::debug("OPC UA server: Setting server config.");
    auto server_config = UA_Server_getConfig(server);
    auto retval = oplc::opcua_server::UA_ServerConfig_setDefaultWithSecurityPolicies(
            server_config,          // *conf,
            4840,         // portNumber,
            &certificate,           // *certificate,
            &private_key,            // *privateKey,
            trusted.data(),         // *trustList,
            trusted.size(),         // trustListSize,
            issuers.data(),                // *issuerList,
            issuers.size(),           // issuerListSize,
            revocation_list.data(),        // *revocationList,
            revocation_list.size(),         // revocationListSize
            config.allow_anonymous,
            config.password_logins
    );


    if (retval != UA_STATUSCODE_GOOD)
    {
        spdlog::error("OPC UA server: Error adding default config.");

        if (certificate.length == 0)
        {
            spdlog::error("OPC UA server: Could not load certificate.");
        }
        if (private_key.length == 0)
        {
            spdlog::error("OPC UA server: Could not load private key.");
            std::cerr << "Could not load private key\n";
        }
        if ((private_key.length != 0) && (certificate.length != 0))
        {
            spdlog::error("OPC UA server: Unknown critical error creating server configuration, exiting.");

        }
        exit(0);
    }
    spdlog::debug("OPC UA server: Cleaning up file descriptors.");
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&private_key);
    for (auto p: trusted)
    { UA_ByteString_clear(&p); }
    for (auto p: revocation_list)
    { UA_ByteString_clear(&p); }
    for (auto p: issuers)
    { UA_ByteString_clear(&p); }
    spdlog::debug("OPC UA server: creating server complete.");
    return server;
}

UA_Server *get_ua_server_without_encryption(const GlueVariablesBinding &binding, const oplc::OpcUaServerConfig &config)
{
    spdlog::debug("OPC UA server: creating server without encryption.");

    auto server = oplc::opcua_server::UA_Server_new();
    spdlog::debug("OPC UA server: Setting server config.");
    auto server_config = UA_Server_getConfig(server);
    auto retval = oplc::opcua_server::UA_ServerConfig_setDefault(server_config);

    if (retval != UA_STATUSCODE_GOOD)
    {
        spdlog::error("OPC UA server: Unknown critical error creating server configuration, exiting.");
        throw std::runtime_error("Critical error creating server configuration.");
    }
    spdlog::debug("OPC UA server: creating server complete.");
    return server;
}


void oplc::opcua_server::opc_ua_service_run(const GlueVariablesBinding &binding,
                                            volatile bool &run, const char *config)
{

    OpcUaServerConfig server_config = get_config();

    auto server = (server_config.encryption_on) ?
                  get_ua_server_with_encryption(binding, server_config) :
                  get_ua_server_without_encryption(binding, server_config);


    spdlog::debug("OPC UA server: Adding program related nodes.");
    auto context_store = add_nodes_to_server(server, binding);
    spdlog::debug("OPC UA server: Running server.");
    auto retval = UA_Server_run(server, &run);
    if (retval != UA_STATUSCODE_GOOD)
    {
        throw std::runtime_error("OPC UA server: Could not run server.");
    }
    //TODO: delete context_store items safely
    // reference: https://stackoverflow.com/questions/16527673/c-one-stdvector-containing-template-class-of-multiple-types
    spdlog::debug("OPC UA server: Stopping server.");
    UA_Server_delete(server);

};