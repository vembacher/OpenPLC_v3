//
// Created by v on 08.10.21.
//

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
    //      a future goal will be that this is configurable and more convient.
    auto certificate = loadFile("/etc/openplc/PKI/own/certs/cert.der");
    auto privateKey = loadFile("/etc/openplc/PKI/own/private/key.der");
    auto trusted_ca = loadFile("/etc/openplc/PKI/trusted/certs/ca-chain.cert.der");
    auto ua_expert = loadFile("/etc/openplc/PKI/trusted/certs/uaexpert.der");
    std::vector<UA_ByteString> trusted{ua_expert, trusted_ca};

    // We need a CRL for every CA, otherwise certificates signed by this CA will NOT be accepted.
    UA_STACKARRAY(UA_ByteString, revocation_list, 1);
    revocation_list[0] = loadFile("/etc/openplc/PKI/trusted/crl/intermediate.crl.pem");

//    std::vector<UA_ByteString> trusted = load_files_in_dir("/etc/openplc/PKI/trusted/certs");
//    std::vector<UA_ByteString> crls = load_files_in_dir("/etc/openplc/PKI/trusted/crl");

    //TODO: handle issuers
    UA_ByteString *issuers = nullptr;
    auto server = UA_Server_new();
    auto server_config = UA_Server_getConfig(server);
    auto retval = UA_ServerConfig_setDefaultWithSecurityPolicies(
            server_config,          //*conf,
            4840,         //portNumber,
            &certificate,           // *certificate,
            &privateKey,            //U*privateKey,
            trusted.data(),         // *trustList,
            trusted.size(),         //trustListSize,
            issuers,                // *issuerList,
            0,           //issuerListSize,
            revocation_list,        //*revocationList,
            1         //revocationListSize
    );

    if (retval != UA_STATUSCODE_GOOD)
    {
        std::cerr << "OPC UA Server: Error adding default config.\n";
        if (certificate.length == 0)
        {
            std::cerr << "Could not load certificate\n";
        }
        if (privateKey.length == 0)
        {
            std::cerr << "Could not load private key\n";
        }
        if (trusted.empty())
        {
            std::cerr << "Could not load trusted\n";
        }
//        if (crls.size() == 0) {
//            std::cerr << "Could not load crls\n";
//        }
        for (const auto &elem: trusted)
        {
            std::cerr << "could not load trusted cert at path: '" << elem.data << "'\n";
        }
//        for (const auto &elem: crls) {
//            std::cerr << "could not load crl at path: '" << elem.data << "'\n";
//        }
    }
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    for (auto p: trusted)
    { UA_ByteString_clear(&p); }
//    for (auto p: crls) { UA_ByteString_clear(&p); }
    UA_ByteString_clear(&revocation_list[0]);
    return server;
}


void oplc::opcua_server::opc_ua_service_run(const GlueVariablesBinding &binding,
                                            volatile bool &run, const char *config)
{


    auto server = get_ua_server_with_encryption(binding, config);


    for (int i = 0; i < binding.size; ++i)
    {
        std::lock_guard<std::mutex> guard(*binding.buffer_lock);
        auto glue = binding.glue_variables[i];
        std::cout << i << "Glue(" << glue.size << "," << glue.type << ")\n";
    }

    auto context_store = add_nodes_to_server(server, binding);
    auto retval = UA_Server_run(server, &run);

    //TODO: delete context_store items safely
    // reference: https://stackoverflow.com/questions/16527673/c-one-stdvector-containing-template-class-of-multiple-types
    UA_Server_delete(server);

};