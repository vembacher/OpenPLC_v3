
#ifndef RUNTIME_CORE_NODES_H

#define RUNTIME_CORE_NODES_H

extern "C" {
#include <open62541/server.h>
}

#include <mutex>
#include <utility>
#include <chrono>

#include "glue.h"
#include <vector>

using namespace std::chrono_literals;


class INodeContext
{
    //TODO: evaluate which methods could be pulled into base class

public:
    std::string name;
    IecGlueValueType type;
    bool writable;

    const UA_DataType *get_ua_type()
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

    virtual ~INodeContext() = default;
};

template<typename T>
class NodeContext : public INodeContext
{
public:

    T read()
    {
        std::lock_guard<std::mutex> cache_lock{mutex_self};

        //check freshness of cached value, if it's too old we grab a fresh value from the glue variable
        if ((std::chrono::system_clock::now() - cache_timestamp) > cache_ttl)
        {
            std::lock_guard<std::mutex> glue_lock{*mutex_glue};
            cache = *value;
        }
        cache_timestamp = std::chrono::system_clock::now();
        return cache;
    }

    void write(T requested_value)
    {
        if (!writable) return;
        std::lock_guard<std::mutex> cache_lock{mutex_self};

        {
            std::lock_guard<std::mutex> glue_guard{*mutex_glue};
            *value = requested_value;
        }
        cache = requested_value;
        cache_timestamp = std::chrono::system_clock::now();
    }

    NodeContext(T *value, std::mutex *mutexGlue, IecGlueValueType type, std::string name, bool writable) :
            value(value), mutex_glue(mutexGlue)
    {
        this->type = type;
        this->name = std::move(name);
        this->writable = writable;
        read(); //update cache, this will update the timestamp;
    }

private:
    T cache;
    T *value;
    std::chrono::time_point<std::chrono::system_clock> cache_timestamp;
    std::chrono::milliseconds cache_ttl = 100ms;
    std::mutex mutex_self;
    std::mutex *mutex_glue;
};


std::vector<INodeContext *> add_nodes_to_server(UA_Server *server, const GlueVariablesBinding &bindings);

#endif //RUNTIME_CORE_NODES_H
