#pragma once

#include <stddef.h>     // for size_t
#include <iostream>     // for ostream
#include <string>       // for string
#include <list>         // for list
#include <map>          // for map, map<>::value_compare
#include <string_view>  // for string_view


namespace nix {


typedef std::map<std::string, std::string> XMLAttrs;


class XMLWriter
{
private:

    std::ostream & output;

    bool indent;
    bool closed;

    std::list<std::string> pendingElems;

public:

    XMLWriter(bool indent, std::ostream & output);
    ~XMLWriter();

    void close();

    void openElement(std::string_view name,
        const XMLAttrs & attrs = XMLAttrs());
    void closeElement();

    void writeEmptyElement(std::string_view name,
        const XMLAttrs & attrs = XMLAttrs());

private:
    void writeAttrs(const XMLAttrs & attrs);

    void indent_(size_t depth);
};


class XMLOpenElement
{
private:
    XMLWriter & writer;
public:
    XMLOpenElement(XMLWriter & writer, std::string_view name,
        const XMLAttrs & attrs = XMLAttrs())
        : writer(writer)
    {
        writer.openElement(name, attrs);
    }
    ~XMLOpenElement()
    {
        writer.closeElement();
    }
};


}
