# Feature: OPC UA Server Support

This readme serves to document [OPC UA](https://en.wikipedia.org/wiki/OPC_Unified_Architecture) implementation in
OpenPLC. OPC UA is an industrial protocol that can be used for both vertical and horizontal (machine2machine)
communication. It provides better security features than currently supported protocols like Modbus. We will use the OPC
UA library [open62541](https://open62541.org/) with the [MbedTLS](https://github.com/ARMmbed/mbedtls) backend.

If anyone wishes to collaborate, feel free to send [me](https://github.com/vembacher) and e-mail.

## Goals

- adhere to standards regarding using OPC UA with PLCs. Note: We will add a prototype version that does not adhere to
  this standard, that will most likely change its interface during development and might disappear after standard
  compliance has been reached. Another possibility is that we will require users to provide their own XML node
  description of those nodes until there is a reliable to generate those inside the runtime, or we can generate the code
  directly.
- improve communication security for OpenPLC by using security features of OPC UA
- do not break potentially existing OpenPLC build pipelines

## ToDo

- [ ] adhere to UA Companion Specification for PLCopen IEC61131-3
  Model [(available here)](https://opcfoundation.org/developer-tools/specifications-opc-ua-information-models/opc-ua-for-plcopen/)
    - [ ] add component that can transform PLC programs to OPC UA nodes
    - [ ] connect these nodes to PLC variables
- [ ] add proper configuration for (frontend, backend)
    - everything related to certificates
    - other OPC UA server related settings
- [ ] update install/build process, so it does not rely on a new CMake being available in the distribution's
  repository (
  currently assumes there to ba CMake with the version > 3.14 to be available.)
- [ ] make sure build does not fail on non-linux environments
- [ ] sort out licensing of added files
- [ ] implement or document an easy way to add PLC programs to the first installation process. **Reasoning:** adding OPC
  UA increases the compilation times by a lot, especially if we are using the DI and PLCOpen nodesets.
- [ ] more ToDos will be added

## Other possible future goals

- move configuration via socket to configuration via OPC UA methods

