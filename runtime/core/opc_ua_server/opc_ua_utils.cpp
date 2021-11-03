

#include <fstream>
#include <vector>
#include <regex>

#include "glue.h"
#include "opc_ua_utils.h"

std::string get_active_progam()
{

    std::ifstream file{"../etc/active_program"};
    if (!file)
    {
        //TODO: clean this up, it's for debugging
        file = std::ifstream{"/workdir/etc/active_program"};
//        return "";
        if (!file) return "";
    }
    std::string result;
    std::getline(file, result);
    return result;
}

IecGlueValueType get_iec_type_from_string(std::string s)
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

/* This function returns variable descriptions from the active program st file.
 * It is done via regex matching and does little to no input validation.
 * In the future this part should get replaced or rather become redundant.
 */
std::vector<VariableDescription> get_variable_descriptions()
{
    //very primitive regex used to parse some information from the active program st file
    std::regex re{
            R"(([A-Za-z_0-9]*) AT (%[IQM](([X][0-9]{1,3}.[0-7])|([BWDL][0-9]{1,3}))) : (BOOL|BYTE|SINT|USINT|INT|UINT|WORD|DINT|UDINT|DWORD|REAL|LREAL|LINT|ULINT))",
            std::regex::ECMAScript};

    std::vector<VariableDescription> result;


    //TODO: re-write the code about getting the active program, it's janky as hell
    auto active_program = get_active_progam();
    auto path = (!active_program.empty()) ? ("./etc/st_files/" + active_program) : "blank_program.st";
    std::ifstream file{path};
    if(!file) {
        file = std::ifstream{"../etc/st_files/" + active_program};
    }
    bool is_var_block = false;
    while (file)
    {
        std::string line;
        std::getline(file, line);
        if (line == "  VAR")
        {
            is_var_block = true;
            continue;
        } else if (line == "  END_VAR")
        {
            is_var_block = false;
            continue;
        } else if (is_var_block)
        {
            std::smatch matches;
            if (std::regex_search(line, matches, re))
            {
                VariableDescription variable;
                variable.name = matches[1];
                variable.location = matches[2];
                variable.type = get_iec_type_from_string(matches[5]);
                result.emplace_back(variable);
            }
        }
    }
    return result;
}

