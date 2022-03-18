#include <fstream>
#include <vector>
#include <regex>
#include <exception>

#include "spdlog/spdlog.h"
#include "glue.h"
#include "opc_ua_utils.h"
#include "opc_ua_server.h"
#include "ini_util.h"
#include "ini.h"

IecGlueValueType get_iec_type_from_string(const std::string &s)
{

    if (s == "BOOL") return IECVT_BOOL;
    else if (s == "BYTE") return IECVT_BYTE;
    else if (s == "SINT") return IECVT_SINT;
    else if (s == "USINT") return IECVT_USINT;
    else if (s == "INT") return IECVT_INT;
    else if (s == "UINT") return IECVT_UINT;
    else if (s == "WORD") return IECVT_WORD;
    else if (s == "DINT") return IECVT_DINT;
    else if (s == "UDINT") return IECVT_UDINT;
    else if (s == "DWORD") return IECVT_DWORD;
    else if (s == "REAL") return IECVT_REAL;
    else if (s == "LREAL") return IECVT_LREAL;
    else if (s == "LWORD") return IECVT_LWORD;
    else if (s == "LINT") return IECVT_LINT;
    else if (s == "ULINT") return IECVT_ULINT;
    return IECVT_UNASSIGNED;
}

const UA_DataType *ua_type_from_iec_type(IecGlueValueType type)
{
    switch (type)
    {
        case (IECVT_BOOL):
            return &UA_TYPES[UA_TYPES_BOOLEAN];
        case (IECVT_SINT):
            return &UA_TYPES[UA_TYPES_SBYTE];
        case (IECVT_USINT):
            return &UA_TYPES[UA_TYPES_BYTE];
        case (IECVT_INT):
            return &UA_TYPES[UA_TYPES_INT16];
        case (IECVT_UINT):
            return &UA_TYPES[UA_TYPES_UINT16];
        case (IECVT_DINT):
            return &UA_TYPES[UA_TYPES_INT32];
        case (IECVT_UDINT):
            return &UA_TYPES[UA_TYPES_UINT32];
        case (IECVT_LINT):
            return &UA_TYPES[UA_TYPES_INT64];
        case (IECVT_ULINT):
            return &UA_TYPES[UA_TYPES_UINT64];
        case (IECVT_BYTE):
            return &UA_TYPES[UA_TYPES_BYTE];
        case (IECVT_WORD):
            return &UA_TYPES[UA_TYPES_UINT16];
        case (IECVT_DWORD):
            return &UA_TYPES[UA_TYPES_UINT32];
        case (IECVT_LWORD):
            return &UA_TYPES[UA_TYPES_UINT64];
        case (IECVT_REAL):
            return &UA_TYPES[UA_TYPES_FLOAT];
        case (IECVT_LREAL):
            return &UA_TYPES[UA_TYPES_DOUBLE];
        default:
            return nullptr;
    }
}

/*
 * Refer to: https://www.openplcproject.com/reference/plc-addressing/
 */
IecLocationSize get_location_size(std::string location)
{
    switch (location[2])
    {
        case 'X':
            return IECLST_BIT;
        case 'B':
            return IECLST_BYTE;
        case 'W':
            return IECLST_WORD;
        case 'D':
            return IECLST_DOUBLEWORD;
        case 'L':
            return IECLST_LONGWORD;
        default:
            throw std::invalid_argument("Invalid Iec Location");
    }
}

/* This function returns variable descriptions from the active program st file.
 * It is done via regex matching and does little to no input validation.
 * In the future this part should get replaced or rather become redundant.
 */
std::vector<VariableDescription> get_variable_descriptions()
{
    //very primitive regex used to parse some information from the active program st file
    std::regex re{
            R"(([A-Za-z_0-9]*) AT (%[IQM](([X]([0-9]{1,3}).([0-7]))|([BWDL]([0-9]{1,3})))) : (BOOL|BYTE|SINT|USINT|INT|UINT|WORD|DINT|UDINT|DWORD|REAL|LREAL|LINT|ULINT))",
            std::regex::ECMAScript};

    std::vector<VariableDescription> result;


    spdlog::debug("OPC UA server: Finding active program.");
    std::ifstream file_active_name{"../etc/active_program"}; //default case
    std::string active_program_name;
    std::ifstream file;
    spdlog::debug("OPC UA server: Opening active program.");
    if (file_active_name)
    {
        std::getline(file_active_name, active_program_name);
        file = std::ifstream("../etc/st_files/" + active_program_name);
    }
    else
    {
        file_active_name = std::ifstream{"./etc/active_program"};
        std::getline(file_active_name, active_program_name);
        file = std::ifstream("./etc/st_files/" + active_program_name);
    }
    spdlog::debug("OPC UA server: Parsing active program.");
    bool is_var_block = false;
    while (file)
    {
        std::string line;
        std::getline(file, line);
        if (line == "  VAR")
        {
            is_var_block = true;
            continue;
        }
        else if (line == "  END_VAR")
        {
            is_var_block = false;
            continue;
        }
        else if (is_var_block)
        {
            std::smatch matches;
            if (std::regex_search(line, matches, re))
            {
                VariableDescription variable;

                variable.name = matches[1];

                //Locations: I -> input, Q -> output, M -> memory
                auto dir = matches[2].str().at(1);
                variable.dir = (dir == 'I') ? (IECLDT_IN) : ((dir == 'Q') ? (IECLDT_OUT) : (IECLDT_MEM));

                variable.size = get_location_size(matches[2]);
                variable.msi = (matches[5].matched) ? std::stoi(matches[5]) : std::stoi(matches[8]);
                variable.lsi = (matches[6].matched) ? std::stoi(matches[6]) : 0;
                variable.type = get_iec_type_from_string(matches[9]);
                result.emplace_back(variable);
            }
        }
    }
    return result;
}

std::vector<oplc::opcua_server::UA_UsernamePasswordLogin> parse_users(const char *path)
{

    //very primitive regex used to parse some information from the active program st file
    std::regex re{
            R"(([A-Za-z0-9]{1,128}),([A-Za-z0-9*.!@#$%^&\(\)\{\}\[\]:;<>,.?\/~_\+\-=|]{8,128}))",
            std::regex::ECMAScript};

    std::vector<oplc::opcua_server::UA_UsernamePasswordLogin> result;
    auto file = std::ifstream(path);
    while (file)
    {
        std::string line;
        std::getline(file, line);
        std::smatch matches;

        if (std::regex_search(line, matches, re))
        {
            std::string user = matches[1];
            std::string password = matches[2];

            auto user_ua = UA_String_fromChars(user.data());
            auto password_ua = UA_String_fromChars(password.data());

            oplc::opcua_server::UA_UsernamePasswordLogin login = {
                    user_ua,
                    password_ua
            };
            result.emplace_back(login);
        }
    }
    return result;

}

std::unordered_map<std::string, oplc::opcua_server::UserRoleType> parse_roles(const char *path)
{

    //very primitive regex used to parse some information from the active program st file
    std::regex re{
            R"(([^\s^,]{1,128}),(admin|operator|observer))",
            std::regex::ECMAScript};

    std::unordered_map<std::string, oplc::opcua_server::UserRoleType> result;
    auto file = std::ifstream(path);
    while (file)
    {
        std::string line;
        std::getline(file, line);
        std::smatch matches;

        if (std::regex_search(line, matches, re))
        {
            std::string user = matches[1];
            std::string role = matches[2];
            if (role == "admin")
                result[user] = oplc::opcua_server::UserRoleType::ADMIN;
            else if (role == "operator")
                result[user] = oplc::opcua_server::UserRoleType::OPERATOR;
            else if (role == "observer")
                result[user] = oplc::opcua_server::UserRoleType::OBSERVER;
            else
                throw std::invalid_argument{"OPC UA server: unsupported role."};
        }
    }
    return result;

}

int opcua_server_cfg_handler(void *user_data, const char *section,
                             const char *name, const char *value)
{
    if (strcmp("opcuaserver", section) != 0)
    {
        return 0;
    }

    auto config = reinterpret_cast<oplc::OpcUaServerConfig *>(user_data);

    if (strcmp(name, "port") == 0)
    {
        char *p_end;
        config->port = std::strtol(value, &p_end, 10);
    }
    else if (strcmp(name, "address") == 0)
    {
        config->address = value;
    }
    else if (strcmp(name, "allow_anonymous") == 0)
    {
        if (strncmp(value, "true", 4) == 0)
            config->allow_anonymous = true;
        else
            config->allow_anonymous = false;
    }
    else if (strcmp(name, "application_uri") == 0)
    {
        config->application_uri = value;
    }
    else if (strcmp(name, "product_uri") == 0)
    {
        config->product_uri = value;
    }
    else if (strcmp(name, "encryption_on") == 0)
    {
        if (strncmp(value, "true", 4) == 0)
            config->encryption_on = true;
        else
            config->encryption_on = false;
    }
    else if (strcmp(name, "server_cert_path") == 0)
    {
        config->server_cert_path = value;
    }
    else if (strcmp(name, "server_pkey_path") == 0)
    {
        config->server_pkey_path = value;
    }
    else if (strcmp(name, "users_path") == 0)
    {
        config->password_logins = parse_users(value);
    }
    else if (strcmp(name, "roles_path") == 0)
    {
        config->user_roles = parse_roles(value);
    }
    else if (strcmp(name, "trust_list_paths") == 0)
    {
        spdlog::warn("OPCUA Server: 'trust_list_paths' config field is not implemented, using default.");
    }
    else if (strcmp(name, "revocation_list_paths") == 0)
    {
        spdlog::warn("OPC UA Server: 'revocation_list_paths' config field is not implemented, using default.");
    }
    else
    {
        spdlog::warn("Unknown configuration item {}", name);
        return -1;
    }

    return 0;
}

oplc::OpcUaServerConfig get_config()
{
    auto config = oplc::OpcUaServerConfig{};
    auto cfg_stream = oplc::open_config();
    ini_parse_stream(oplc::istream_fgets, cfg_stream.get(),
                     opcua_server_cfg_handler, &config);
    return config;
}