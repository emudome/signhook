#include "pch.h"
#include "signed_data.h"
#include <sstream>
#include <fstream>
#include <iostream>
#include "json.hpp"

/**
 * @brief Default constructor for the SigningData class.
 */
SignedData::SignedData()
	: signed_digest_()
	, encoded_cert_()
	, cert_encoding_type_(0)
{
}

/**
 * @brief Constructor for the SigningData class.
 * 
 * @param signed_digest The signed digest.
 * @param encoded_cert The encoded certificate.
 * @param cert_encoding_type The certificate encoding type.
 */
SignedData::SignedData(const std::vector<BYTE>& signed_digest, const std::vector<BYTE>& encoded_cert, DWORD cert_encoding_type)
	: signed_digest_(signed_digest)
	, encoded_cert_(encoded_cert)
	, cert_encoding_type_(cert_encoding_type) {

}

/**
 * @brief Load SigningData object from a JSON string.
 * 
 * This function parses a JSON string and constructs a SigningData object from the parsed data.
 * The JSON string should have the following format:
 * {
 *     "signed_digest": "<hex_string>",
 *     "encoded_cert": "<hex_string>",
 *     "cert_encoding_type": <number>
 * }
 * 
 * @param json_string The JSON string to parse.
 * @return The constructed SigningData object.
 * @throws std::runtime_error if the JSON string parsing fails.
 */
SignedData SignedData::LoadFromString(const std::string& json_string) {
    auto StrToHex = [](const std::string& hex_str) -> std::vector<BYTE> {
        std::vector<BYTE> bytes;
        for (size_t i = 0; i < hex_str.length(); i += 2) {
            std::string byteString = hex_str.substr(i, 2);
            BYTE byte = static_cast<BYTE>(strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
        };

    auto json_data = nlohmann::json::parse(json_string);
    auto signed_digest = StrToHex(json_data["signed_digest"].get<std::string>());
    auto encoded_cert = StrToHex(json_data["encoded_cert"].get<std::string>());
    auto cert_encoding_type = static_cast<DWORD>(json_data.at("cert_encoding_type").get<double>());

    return SignedData(signed_digest, encoded_cert, cert_encoding_type);
}
