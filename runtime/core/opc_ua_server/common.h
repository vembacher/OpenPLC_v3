/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

extern "C" {
#include <open62541/types.h>
#include <open62541/types_generated_handling.h>
}


#include <dirent.h>
#include <iostream>


/* loadFile parses the certificate file.
 *
 * @param  path               specifies the file name given in argv[]
 * @return Returns the file content after parsing */
static UA_INLINE UA_ByteString
loadFile(const char *const path)
{
    UA_ByteString fileContents = UA_STRING_NULL;

    /* Open the file */
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        errno = 0; /* We read errno also from the tcp layer... */
        return fileContents;
    }

    /* Get the file length, allocate the data and read */
    fseek(fp, 0, SEEK_END);
    fileContents.length = (size_t) ftell(fp);
    fileContents.data = (UA_Byte *) UA_malloc(fileContents.length * sizeof(UA_Byte));
    if (fileContents.data) {
        fseek(fp, 0, SEEK_SET);
        size_t read = fread(fileContents.data, sizeof(UA_Byte), fileContents.length, fp);
        if (read != fileContents.length)
            UA_ByteString_clear(&fileContents);
    } else {
        fileContents.length = 0;
    }
    fclose(fp);

    return fileContents;
}

static UA_INLINE UA_StatusCode
writeFile(const char *const path, const UA_ByteString buffer)
{
    FILE *fp = nullptr;

    fp = fopen(path, "wb");
    if (fp == nullptr)
        return UA_STATUSCODE_BADINTERNALERROR;

    for (UA_UInt32 bufIndex = 0; bufIndex < buffer.length; bufIndex++) {
        int retVal = fputc(buffer.data[bufIndex], fp);
        if (retVal == EOF) {
            fclose(fp);
            return UA_STATUSCODE_BADINTERNALERROR;
        }
    }

    fclose(fp);
    return UA_STATUSCODE_GOOD;
}

std::vector<std::string> list_dir(const std::string &path)
{
    DIR *dir;
    dirent *ent;
    std::vector<std::string> result;
    if ((dir = opendir(path.c_str())) != nullptr) {
        while ((ent = readdir(dir)) != nullptr) {
            result.emplace_back(ent->d_name);
        }
        closedir(dir);
    } else {
        std::cerr << "Could not open directory: '" << path << "'\n";
    }
    return result;
}

std::vector<UA_ByteString> load_files_in_dir(std::string dir_path)
{
    std::vector<UA_ByteString> result;
    for (const auto &elem: list_dir(dir_path)) {
        if (elem != "." && elem != "..") { result.emplace_back(loadFile(elem.c_str())); }
    }
    return result;
}