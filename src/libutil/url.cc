#include <string.h>          // for strchr, size_t
#include <boost/format.hpp>  // for basic_altstringbuf<>::int_type, basic_al...
#include <list>              // for list, operator!=, _List_iterator, _List_...
#include <regex>             // for sub_match, regex, match_results, _NFA
#include <sstream>           // for basic_stringbuf<>::int_type, basic_strin...
#include <type_traits>       // for add_const<>::type
#include <utility>           // for tuple_element<>::type
#include <vector>            // for vector
#include <algorithm>         // for equal

#include "url.hh"
#include "url-parts.hh"      // for queryRegex, absPathRegex, authorityRegex
#include "util.hh"           // for tokenizeString
#include "split.hh"          // for splitPrefixTo
#include "libutil/fmt.hh"    // for fmt
#include "libutil/types.hh"  // for Strings

namespace nix {

std::regex refRegex(refRegexS, std::regex::ECMAScript);
std::regex badGitRefRegex(badGitRefRegexS, std::regex::ECMAScript);
std::regex revRegex(revRegexS, std::regex::ECMAScript);
std::regex flakeIdRegex(flakeIdRegexS, std::regex::ECMAScript);

ParsedURL parseURL(const std::string & url)
{
    static std::regex uriRegex(
        "((" + schemeRegex + "):"
        + "(?:(?://(" + authorityRegex + ")(" + absPathRegex + "))|(/?" + pathRegex + ")))"
        + "(?:\\?(" + queryRegex + "))?"
        + "(?:#(" + queryRegex + "))?",
        std::regex::ECMAScript);

    std::smatch match;

    if (std::regex_match(url, match, uriRegex)) {
        auto & base = match[1];
        std::string scheme = match[2];
        auto authority = match[3].matched
            ? std::optional<std::string>(match[3]) : std::nullopt;
        std::string path = match[4].matched ? match[4] : match[5];
        auto & query = match[6];
        auto & fragment = match[7];

        auto isFile = scheme.find("file") != std::string::npos;

        if (authority && *authority != "" && isFile)
            throw BadURL("file:// URL '%s' has unexpected authority '%s'",
                url, *authority);

        if (isFile && path.empty())
            path = "/";

        return ParsedURL{
            .url = url,
            .base = base,
            .scheme = scheme,
            .authority = authority,
            .path = path,
            .query = decodeQuery(query),
            .fragment = percentDecode(std::string(fragment))
        };
    }

    else
        throw BadURL("'%s' is not a valid URL", url);
}

std::string percentDecode(std::string_view in)
{
    std::string decoded;
    for (size_t i = 0; i < in.size(); ) {
        if (in[i] == '%') {
            if (i + 2 >= in.size())
                throw BadURL("invalid URI parameter '%s'", in);
            try {
                decoded += std::stoul(std::string(in, i + 1, 2), 0, 16);
                i += 3;
            } catch (...) {
                throw BadURL("invalid URI parameter '%s'", in);
            }
        } else
            decoded += in[i++];
    }
    return decoded;
}

std::map<std::string, std::string> decodeQuery(const std::string & query)
{
    std::map<std::string, std::string> result;

    for (auto s : tokenizeString<Strings>(query, "&")) {
        auto e = s.find('=');
        if (e != std::string::npos)
            result.emplace(
                s.substr(0, e),
                percentDecode(std::string_view(s).substr(e + 1)));
    }

    return result;
}

std::string percentEncode(std::string_view s)
{
    std::string res;
    for (auto & c : s)
        if ((c >= 'a' && c <= 'z')
            || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9')
            || strchr("-._~!$&'()*+,;=:@", c))
            res += c;
        else
            res += fmt("%%%02x", (unsigned int) c);
    return res;
}

std::string encodeQuery(const std::map<std::string, std::string> & ss)
{
    std::string res;
    bool first = true;
    for (auto & [name, value] : ss) {
        if (!first) res += '&';
        first = false;
        res += percentEncode(name);
        res += '=';
        res += percentEncode(value);
    }
    return res;
}

std::string ParsedURL::to_string() const
{
    return
        scheme
        + ":"
        + (authority ? "//" + *authority : "")
        + path
        + (query.empty() ? "" : "?" + encodeQuery(query))
        + (fragment.empty() ? "" : "#" + percentEncode(fragment));
}

bool ParsedURL::operator ==(const ParsedURL & other) const
{
    return
        scheme == other.scheme
        && authority == other.authority
        && path == other.path
        && query == other.query
        && fragment == other.fragment;
}

/**
 * Parse a URL scheme of the form '(applicationScheme\+)?transportScheme'
 * into a tuple '(applicationScheme, transportScheme)'
 *
 * > parseUrlScheme("http") == ParsedUrlScheme{ {}, "http"}
 * > parseUrlScheme("tarball+http") == ParsedUrlScheme{ {"tarball"}, "http"}
 */
ParsedUrlScheme parseUrlScheme(std::string_view scheme)
{
    auto application = splitPrefixTo(scheme, '+');
    auto transport = scheme;
    return ParsedUrlScheme {
        .application = application,
        .transport = transport,
    };
}

}
