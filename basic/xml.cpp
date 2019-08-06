//
// Created by remco on 06-08-19.
//

#include "xml.h"

std::string xmlEscape(const std::string &in) {
    std::string out;
    for (auto c : in)
        switch (c) {
            case '"':
                out += "&quot;";
                break;
            case '\'':
                out += "&apos;";
                break;
            case '&':
                out += "&amp;";
                break;
            case '<':
                out += "&lt;";
                break;
            case '>':
                out += "&gt;";
                break;
            default:
                out += c;
        }
    return out;
}
