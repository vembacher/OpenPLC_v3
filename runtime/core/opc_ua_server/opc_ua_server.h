#ifndef RUNTIME_CORE_OPC_UA_SERVER_H
#define RUNTIME_CORE_OPC_UA_SERVER_H

#include <cstdint>
#include <vector>
#include "glue.h"
#include "access_control.h"

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
                product_uri("https://github.com/vembacher/OpenPLC_v3"),
                encryption_on(true),
                allow_anonymous(true),
                server_cert_path("../etc/PKI/own/certs/plc.crt.der"),
                server_pkey_path("../etc/PKI/own/private/plc.key.der"),
                trust_list_paths({
                                         "../etc/PKI/trusted/certs/uaexpert.der"
                                         "../etc/PKI/trusted/certs/ca.crt.der",
                                 }),
                issuers_paths({
                              }),
                revocation_list_paths({
                                              "../etc/PKI/trusted/crl/ca.crl"
                                      })
        {}

        // general info
        std::string address;
        std::string application_uri;
        std::string product_uri;

        // security settings
        bool encryption_on;
        std::string server_cert_path;
        std::string server_pkey_path;
        std::vector<std::string> trust_list_paths;
        std::vector<std::string> issuers_paths;
        std::vector<std::string> revocation_list_paths;
        std::vector<oplc::opcua_server::UA_UsernamePasswordLogin> password_logins;
        std::unordered_map<std::string, opcua_server::UserRoleType> user_roles;

        bool allow_anonymous;

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
