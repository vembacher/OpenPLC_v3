#ifndef RUNTIME_CORE_OPC_UA_UTILS_H
#define RUNTIME_CORE_OPC_UA_UTILS_H

extern "C" {
#include <open62541/types.h>
#include <open62541/server.h>
};

#include "glue.h"
#include "opc_ua_server.h"
#include "server_config.h"

struct VariableDescription
{
    IecLocationDirection dir;
    IecLocationSize size;
    std::uint16_t msi;
    IecGlueValueType type;
    std::uint8_t lsi;
    std::string name;
};

std::vector<VariableDescription> get_variable_descriptions();

oplc::OpcUaServerConfig get_config();

// reference https://reference.opcfoundation.org/v104/PackML/v100/docs/C.1/
const UA_DataType *ua_type_from_iec_type(IecGlueValueType type);

inline std::string ua_string_to_cstring(UA_String *ua_string)
{
    char *convert = (char *) UA_malloc(sizeof(char) * ua_string->length + 1);
    memcpy(convert, ua_string->data, ua_string->length);
    convert[ua_string->length] = '\0';
    auto result = std::string{convert};
    UA_free(convert);
    return result;
}

#endif //RUNTIME_CORE_OPC_UA_UTILS_H
