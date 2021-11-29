//
// Created by v on 14.10.21.
//

#ifndef RUNTIME_CORE_OPC_UA_UTILS_H
#define RUNTIME_CORE_OPC_UA_UTILS_H

extern "C" {
#include <open62541/types.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
};

#include "glue.h"


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

// reference https://reference.opcfoundation.org/v104/PackML/v100/docs/C.1/
const UA_DataType *ua_type_from_iec_type(IecGlueValueType type);

#endif //RUNTIME_CORE_OPC_UA_UTILS_H
