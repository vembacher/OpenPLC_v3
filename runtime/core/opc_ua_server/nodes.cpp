

#include <mutex>
#include <vector>
#include <chrono>
#include <functional>

extern "C" {
#include <open62541/server.h>
#include <open62541/plugin/log_stdout.h>
}

#include "nodes.h"
#include "opc_ua_utils.h"


template<typename T>
static void
updateCurrentValue(UA_Server *server, NodeContext<T> *context)
{

    T data;
    data = context->read();
    UA_Variant value;
    UA_Variant_setScalar(&value, &data, context->get_ua_type());
    UA_NodeId currentNodeId = UA_NODEID_STRING(1, &context->name[0]);
    UA_Server_writeValue(server, currentNodeId, value);
}

template<typename T>
static void
beforeReadValue(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext, const UA_NodeId *nodeid,
                void *nodeContext, const UA_NumericRange *range, const UA_DataValue *data)
{
    updateCurrentValue<T>(server, static_cast<NodeContext<T> *>(nodeContext));
}

template<typename T>
static void afterWriteValue(UA_Server *server,
                            const UA_NodeId *sessionId, void *sessionContext,
                            const UA_NodeId *nodeId, void *nodeContext,
                            const UA_NumericRange *range, const UA_DataValue *data)
{
    //sessionId->identifier.numeric != 1 should catch scenario where we write again to the context after just reading
    //because this methond is called after we call 'UA_Server_writeValue(server, currentNodeId, value);'
    // in updateCurrentValue
    if (sessionId->identifier.numeric != 1 && data->hasValue)
    {
        auto context = static_cast<NodeContext<T> *>(nodeContext);
        context->write(*static_cast<T *>(data->value.data));
    }
}


template<typename T>
static
UA_NodeId addVariable(
        UA_Server *server,
        NodeContext<T> *context
)
{
    auto name = &context->name[0]; //we need a non-const char point/C string so the compiler does not complain for CXX11+
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    char locale[]{"en-US"};
    attr.displayName = UA_LOCALIZEDTEXT(locale, name);
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;

    T now;

    //the call context->get_ua_type() is kind of ugly in my opinion, but I wasn't able to find a better solution
    UA_Variant_setScalar(&attr.value, &now, context->get_ua_type());
    UA_NodeId currentNodeId = UA_NODEID_STRING(1, name);
    UA_QualifiedName currentName = UA_QUALIFIEDNAME(1, name);
    UA_NodeId parentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    UA_NodeId parentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
    UA_NodeId variableTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE);

    UA_Server_addVariableNode(server, currentNodeId, parentNodeId, parentReferenceNodeId, currentName,
                              variableTypeNodeId, attr, context, NULL);

    UA_ValueCallback callback;
    callback.onRead = beforeReadValue<T>;
    callback.onWrite = afterWriteValue<T>;
    UA_Server_setVariableNode_valueCallback(server, currentNodeId, callback);

    updateCurrentValue<T>(server, context);
//    context_store.emplace_back(context);
    return currentNodeId;
}

template<typename T>
T *find_if(std::vector<T> &vec, std::function<bool(T)> predicate)
{
    for (auto &elem: vec)
        if (predicate(elem))
        { return &elem; }

    return nullptr;
}

std::vector<INodeContext *> add_nodes_to_server(UA_Server *server, const GlueVariablesBinding &bindings)
{


    auto variables = get_variable_descriptions();
    std::vector<INodeContext *> context_store; //FIXME: prevent this from leaking
    for (int i = 0; i < bindings.size; ++i)
    {
        auto p = &variables[i];
        auto glue_var = bindings.glue_variables[i];
        if (glue_var.type != IECVT_BOOL)
        {
            auto prog_var = find_if<VariableDescription>(variables, [&glue_var](const VariableDescription &var)
            {
                return (glue_var.dir == var.dir) && (glue_var.size == var.size)
                       && (glue_var.msi == var.msi) && (glue_var.lsi == var.lsi);
            });
            switch (glue_var.type)
            {
                case (IECVT_SINT):
                {
                    auto context = new NodeContext<UA_SByte>{
                            static_cast<UA_SByte *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_SByte>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_USINT):
                {

                    auto context = new NodeContext<UA_Byte>{
                            static_cast<UA_Byte *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_Byte>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_INT):
                {
                    auto context = new NodeContext<UA_Int16>{
                            static_cast<UA_Int16 *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_Int16>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_UINT):
                {
                    auto context = new NodeContext<UA_UInt16>{
                            static_cast<UA_UInt16 *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_UInt16>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_DINT):
                {
                    auto context = new NodeContext<UA_Int32>{
                            static_cast<UA_Int32 *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_Int32>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_UDINT):
                {
                    auto context = new NodeContext<UA_UInt32>{
                            static_cast<UA_UInt32 *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_UInt32>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_LINT):
                {
                    auto context = new NodeContext<UA_Int64>{
                            static_cast<UA_Int64 *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_Int64>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_ULINT):
                {
                    auto context = new NodeContext<UA_UInt64>{
                            static_cast<UA_UInt64 *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_UInt64>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_BYTE):
                {
                    auto context = new NodeContext<UA_Byte>{
                            static_cast<UA_Byte *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_Byte>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_WORD):
                {
                    auto context = new NodeContext<UA_UInt16>{
                            static_cast<UA_UInt16 *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_UInt16>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_DWORD):
                {
                    auto context = new NodeContext<UA_UInt32>{
                            static_cast<UA_UInt32 *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_UInt32>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_LWORD):
                {
                    auto context = new NodeContext<UA_UInt64>{
                            static_cast<UA_UInt64 *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_UInt64>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_REAL):
                {
                    auto context = new NodeContext<UA_Float>{
                            static_cast<UA_Float *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_Float>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                case (IECVT_LREAL):
                {
                    auto context = new NodeContext<UA_Double>{
                            static_cast<UA_Double *>(glue_var.value),
                            bindings.buffer_lock,
                            glue_var.type,
                            prog_var->name
                    };
                    addVariable<UA_Double>(server, context);
                    context_store.emplace_back(context);
                    break;
                }
                default:
                    break;
            }
        } else
        {
            auto glue_group = reinterpret_cast<const GlueBoolGroup *>(glue_var.value);
            for (int j = 0; j < 8; ++j)
            {
                if (!glue_group->values[j])
                { continue; }
                auto prog_var = find_if<VariableDescription>(variables, [&glue_var, &j](const VariableDescription &var)
                {
                    return (glue_var.dir == var.dir) && (glue_var.size == var.size)
                           && (glue_var.msi == var.msi) && (glue_var.lsi + j == var.lsi);
                });

                // cast from 'IEC_BOOL *' (aka 'unsigned char *') to 'UA_Boolean *' (aka 'bool *')
                // can only work if their size is equal
                // This ideally should be rewritten
                static_assert(sizeof(bool) == sizeof(unsigned char),
                              "This part assumes we can convert from bools to unsigned chars.");
                auto context = new NodeContext<UA_Boolean>{
                        reinterpret_cast<UA_Boolean *>(glue_group->values[j]),
                        bindings.buffer_lock,
                        glue_var.type,
                        prog_var->name
                };
                addVariable<UA_Boolean>(server, context);
                context_store.emplace_back(context);
            }
        }

    }
    return context_store;
}
