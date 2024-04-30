#pragma once
#include "signer.h"
#include "signed_data.h"

class HttpCommunicator;

class RemoteSigner : public ISigner {
private:
	std::shared_ptr<HttpCommunicator> communicator_;
public:
    RemoteSigner(const std::string& json_string);
    SignedData Sign(
        const std::wstring& digest_algorithm,
        const std::vector<unsigned char>& to_be_signed_digest
    ) override;
};
