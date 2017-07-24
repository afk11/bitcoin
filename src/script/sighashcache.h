#include <boost/thread.hpp>
#include "crypto/sha256.h"
#include "hash.h"

class CSignatureHashCache {
private:
    typedef std::map <uint256, uint256> hashMap;
    mutable hashMap setValid;
    mutable boost::shared_mutex cs_sighashcache;

public:
    CSignatureHashCache() {}

    void ComputeEntry(uint256 entry, const CScript &scriptCode, int nHashType, SigVersion sigversion) const {
        CHashWriter ss(SER_GETHASH, 0);
        ss << scriptCode << nHashType << int(sigversion);
        entry = ss.GetHash();
    }

    bool Get(const uint256& entry, uint256& value) const {
        boost::shared_lock<boost::shared_mutex> lock(cs_sighashcache);
        std::map<uint256,uint256>::iterator it = setValid.find(entry);
        if (it == setValid.end()) {
            return false;
        }
        value = it->second;
        return true;
    }

    void Set(uint256& entry, uint256& value) const {
        boost::unique_lock<boost::shared_mutex> lock(cs_sighashcache);
        setValid.insert(std::pair<uint256,uint256>(entry, value));
    }
};