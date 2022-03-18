/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2016-2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */

#ifndef RUNTIME_CORE_CONTROL_H
#define RUNTIME_CORE_CONTROL_H


#include <unordered_map>
#include <string>

extern "C" {
#include <open62541/plugin/accesscontrol.h>
#include <open62541/server.h>
}
namespace oplc
{
    namespace opcua_server
    {

        enum UserRoleType
        {
            ADMIN,
            OPERATOR,
            OBSERVER,
        };

        typedef struct
        {
            UA_String username;
            UA_String password;
        } UA_UsernamePasswordLogin;

        /* Default access control. The log-in can be anonymous or username-password. A
         * logged-in user has all access rights.
         *
         * The certificate verification plugin lifecycle is moved to the access control
         * system. So it is cleared up eventually together with the AccessControl. */
        UA_StatusCode
        UA_AccessControl_default(UA_ServerConfig *config, UA_Boolean allowAnonymous,
                                 UA_CertificateVerification *verifyX509,
                                 const UA_ByteString *userTokenPolicyUri, size_t usernamePasswordLoginSize,
                                 const UA_UsernamePasswordLogin *usernamePasswordLogin,
                                 std::unordered_map<std::string, opcua_server::UserRoleType> userRoles);
    }
}
#endif //RUNTIME_CORE_CONTROL_H
