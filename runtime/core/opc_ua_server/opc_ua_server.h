#ifndef RUNTIME_CORE_OPC_UA_SERVER_H
#define RUNTIME_CORE_OPC_UA_SERVER_H

#include <cstdint>
#include <vector>
#include "glue.h"

/** \addtogroup openplc_runtime
 *  @{
 */


/// @brief Start the opc ua server.
///
/// @param binding The glue variables that may be bound into this
///                       server.
/// @param run A signal for running this server. This server terminates when
///            this signal is false.
/// @param config The custom configuration for this service.
namespace oplc
{
    struct OpcUaServerConfig
    {
        OpcUaServerConfig() :
                port(4840),
                address("127.0.0.1"),
                application_uri("urn:localhost:OpenPLCProject:OpenPLC"),
                product_uri("https://github.com/thiagoralves/OpenPLC_v3"),
                server_cert(false)
        {}

        // general info
        std::string address;
        std::string application_uri;
        std::string product_uri;

        // security settings
        bool server_cert;
        std::string server_cert_path;
        std::string server_pkey_path;
        std::vector<std::string> trust_list_paths;
        std::vector<std::string> issuer_list_paths;
        std::vector<std::string> revocation_list_paths;

        uint16_t port;
    };
    namespace opcua_server
    {
        void opc_ua_service_run(const GlueVariablesBinding &binding,
                                volatile bool &run, const char *config);
    }
}




/** @} */


#endif //RUNTIME_CORE_OPC_UA_SERVER_H
