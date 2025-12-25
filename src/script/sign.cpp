// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sign.h>

#include <consensus/amount.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/keyorigin.h>
#include <script/miniscript.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <uint256.h>
#include <util/translation.h>
#include <util/vector.h>

typedef std::vector<unsigned char> valtype;

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const CAmount& amount, int hash_type)
    : m_txto{tx}, nIn{input_idx}, nHashType{hash_type}, amount{amount}, checker{&m_txto, nIn, amount, MissingDataBehavior::FAIL},
      m_txdata(nullptr)
{
}

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const CAmount& amount, const PrecomputedTransactionData* txdata, int hash_type)
    : m_txto{tx}, nIn{input_idx}, nHashType{hash_type}, amount{amount},
      checker{txdata ? MutableTransactionSignatureChecker{&m_txto, nIn, amount, *txdata, MissingDataBehavior::FAIL} :
                       MutableTransactionSignatureChecker{&m_txto, nIn, amount, MissingDataBehavior::FAIL}},
      m_txdata(txdata)
{
}

bool MutableTransactionSignatureCreator::CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& address, const CScript& scriptCode, SigVersion sigversion) const
{
    assert(sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0);

    CKey key;
    if (!provider.GetKey(address, key))
        return false;

    // Signing without known amount does not work in witness scripts.
    if (sigversion == SigVersion::WITNESS_V0 && !MoneyRange(amount)) return false;

    // BASE/WITNESS_V0 signatures don't support explicit SIGHASH_DEFAULT, use SIGHASH_ALL instead.
    const int hashtype = nHashType == SIGHASH_DEFAULT ? SIGHASH_ALL : nHashType;

    uint256 hash = SignatureHash(scriptCode, m_txto, nIn, hashtype, amount, sigversion, m_txdata);
    if (!key.Sign(hash, vchSig))
        return false;
    vchSig.push_back((unsigned char)hashtype);
    return true;
}

static bool GetCScript(const SigningProvider& provider, const SignatureData& sigdata, const CScriptID& scriptid, CScript& script)
{
    if (provider.GetCScript(scriptid, script)) {
        return true;
    }
    // Look for scripts in SignatureData
    if (CScriptID(sigdata.redeem_script) == scriptid) {
        script = sigdata.redeem_script;
        return true;
    } else if (CScriptID(sigdata.witness_script) == scriptid) {
        script = sigdata.witness_script;
        return true;
    }
    return false;
}

static bool GetPubKey(const SigningProvider& provider, const SignatureData& sigdata, const CKeyID& address, CPubKey& pubkey)
{
    // Look for pubkey in all partial sigs
    const auto it = sigdata.signatures.find(address);
    if (it != sigdata.signatures.end()) {
        pubkey = it->second.first;
        return true;
    }
    // Look for pubkey in pubkey lists
    const auto& pk_it = sigdata.misc_pubkeys.find(address);
    if (pk_it != sigdata.misc_pubkeys.end()) {
        pubkey = pk_it->second.first;
        return true;
    }
    // Query the underlying provider
    return provider.GetPubKey(address, pubkey);
}

static bool CreateSig(const BaseSignatureCreator& creator, SignatureData& sigdata, const SigningProvider& provider, std::vector<unsigned char>& sig_out, const CPubKey& pubkey, const CScript& scriptcode, SigVersion sigversion)
{
    CKeyID keyid = pubkey.GetID();
    const auto it = sigdata.signatures.find(keyid);
    if (it != sigdata.signatures.end()) {
        sig_out = it->second.second;
        return true;
    }
    KeyOriginInfo info;
    if (provider.GetKeyOrigin(keyid, info)) {
        sigdata.misc_pubkeys.emplace(keyid, std::make_pair(pubkey, std::move(info)));
    }
    if (creator.CreateSig(provider, sig_out, keyid, scriptcode, sigversion)) {
        auto i = sigdata.signatures.emplace(keyid, SigPair(pubkey, sig_out));
        assert(i.second);
        return true;
    }
    // Could not make signature or signature not found, add keyid to missing
    sigdata.missing_sigs.push_back(keyid);
    return false;
}

template<typename M, typename K, typename V>
miniscript::Availability MsLookupHelper(const M& map, const K& key, V& value)
{
    auto it = map.find(key);
    if (it != map.end()) {
        value = it->second;
        return miniscript::Availability::YES;
    }
    return miniscript::Availability::NO;
}

/**
 * Context for solving a Miniscript.
 * If enough material (access to keys, hash preimages, ..) is given, produces a valid satisfaction.
 */
template<typename Pk>
struct Satisfier {
    using Key = Pk;

    const SigningProvider& m_provider;
    SignatureData& m_sig_data;
    const BaseSignatureCreator& m_creator;
    const CScript& m_witness_script;
    //! The context of the script we are satisfying (P2WSH only).
    const miniscript::MiniscriptContext m_script_ctx;

    explicit Satisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                       const BaseSignatureCreator& creator LIFETIMEBOUND,
                       const CScript& witscript LIFETIMEBOUND,
                       miniscript::MiniscriptContext script_ctx) : m_provider(provider),
                                                                   m_sig_data(sig_data),
                                                                   m_creator(creator),
                                                                   m_witness_script(witscript),
                                                                   m_script_ctx(script_ctx) {}

    static bool KeyCompare(const Key& a, const Key& b) {
        return a < b;
    }

    //! Get a CPubKey from a key hash.
    template<typename I>
    std::optional<CPubKey> CPubFromPKHBytes(I first, I last) const {
        assert(last - first == 20);
        CPubKey pubkey;
        CKeyID key_id;
        std::copy(first, last, key_id.begin());
        if (GetPubKey(m_provider, m_sig_data, key_id, pubkey)) return pubkey;
        m_sig_data.missing_pubkeys.push_back(key_id);
        return {};
    }

    //! Conversion to raw public key.
    std::vector<unsigned char> ToPKBytes(const Key& key) const { return {key.begin(), key.end()}; }

    //! Time lock satisfactions.
    bool CheckAfter(uint32_t value) const { return m_creator.Checker().CheckLockTime(CScriptNum(value)); }
    bool CheckOlder(uint32_t value) const { return m_creator.Checker().CheckSequence(CScriptNum(value)); }

    //! Hash preimage satisfactions.
    miniscript::Availability SatSHA256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.sha256_preimages, hash, preimage);
    }
    miniscript::Availability SatRIPEMD160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.ripemd160_preimages, hash, preimage);
    }
    miniscript::Availability SatHASH256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.hash256_preimages, hash, preimage);
    }
    miniscript::Availability SatHASH160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.hash160_preimages, hash, preimage);
    }

    miniscript::MiniscriptContext MsContext() const {
        return m_script_ctx;
    }
};

/** Miniscript satisfier specific to P2WSH context. */
struct WshSatisfier: Satisfier<CPubKey> {
    explicit WshSatisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                          const BaseSignatureCreator& creator LIFETIMEBOUND, const CScript& witscript LIFETIMEBOUND)
                          : Satisfier(provider, sig_data, creator, witscript, miniscript::MiniscriptContext::P2WSH) {}

    //! Conversion from a raw compressed public key.
    template <typename I>
    std::optional<CPubKey> FromPKBytes(I first, I last) const {
        CPubKey pubkey{first, last};
        if (pubkey.IsValid()) return pubkey;
        return {};
    }

    //! Conversion from a raw compressed public key hash.
    template<typename I>
    std::optional<CPubKey> FromPKHBytes(I first, I last) const {
        return Satisfier::CPubFromPKHBytes(first, last);
    }

    //! Satisfy an Post Quantum signature check.
    miniscript::Availability Sign(const CPubKey& key, std::vector<unsigned char>& sig) const {
        if (CreateSig(m_creator, m_sig_data, m_provider, sig, key, m_witness_script, SigVersion::WITNESS_V0)) {
            return miniscript::Availability::YES;
        }
        return miniscript::Availability::NO;
    }
};

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
 * unless whichTypeRet is TxoutType::SCRIPTHASH, in which case scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */
static bool SignStep(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& scriptPubKey,
                     std::vector<valtype>& ret, TxoutType& whichTypeRet, SigVersion sigversion, SignatureData& sigdata)
{
    CScript scriptRet;
    ret.clear();
    std::vector<unsigned char> sig;

    std::vector<valtype> vSolutions;
    whichTypeRet = Solver(scriptPubKey, vSolutions);

    switch (whichTypeRet) {
    case TxoutType::NONSTANDARD:
    case TxoutType::NULL_DATA:
        return false;
    case TxoutType::PUBKEY:
        if (!CreateSig(creator, sigdata, provider, sig, CPubKey(vSolutions[0]), scriptPubKey, sigversion)) return false;
        ret.push_back(std::move(sig));
        return true;
    case TxoutType::PUBKEYHASH: {
        CKeyID keyID = CKeyID(uint160(vSolutions[0]));
        CPubKey pubkey;
        if (!GetPubKey(provider, sigdata, keyID, pubkey)) {
            // Pubkey could not be found, add to missing
            sigdata.missing_pubkeys.push_back(keyID);
            return false;
        }
        if (!CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, sigversion)) return false;
        ret.push_back(std::move(sig));
        ret.push_back(ToByteVector(pubkey));
        return true;
    }
    case TxoutType::SCRIPTHASH: {
        uint160 h160{vSolutions[0]};
        if (GetCScript(provider, sigdata, CScriptID{h160}, scriptRet)) {
            ret.emplace_back(scriptRet.begin(), scriptRet.end());
            return true;
        }
        // Could not find redeemScript, add to missing
        sigdata.missing_redeem_script = h160;
        return false;
    }
    case TxoutType::MULTISIG: {
        size_t required = vSolutions.front()[0];
        ret.emplace_back(); // workaround CHECKMULTISIG bug
        for (size_t i = 1; i < vSolutions.size() - 1; ++i) {
            CPubKey pubkey = CPubKey(vSolutions[i]);
            // We need to always call CreateSig in order to fill sigdata with all
            // possible signatures that we can create. This will allow further PSBT
            // processing to work as it needs all possible signature and pubkey pairs
            if (CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, sigversion)) {
                if (ret.size() < required + 1) {
                    ret.push_back(std::move(sig));
                }
            }
        }
        bool ok = ret.size() == required + 1;
        for (size_t i = 0; i + ret.size() < required + 1; ++i) {
            ret.emplace_back();
        }
        return ok;
    }
    case TxoutType::WITNESS_V0_KEYHASH:
        ret.push_back(vSolutions[0]);
        return true;

    case TxoutType::WITNESS_V0_SCRIPTHASH:
        if (GetCScript(provider, sigdata, CScriptID{RIPEMD160(vSolutions[0])}, scriptRet)) {
            ret.emplace_back(scriptRet.begin(), scriptRet.end());
            return true;
        }
        // Could not find witnessScript, add to missing
        sigdata.missing_witness_script = uint256(vSolutions[0]);
        return false;

    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else if (v.size() == 1 && v[0] == 0x81) {
            result << OP_1NEGATE;
        } else {
            result << v;
        }
    }
    return result;
}

bool ProduceSignature(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& fromPubKey, SignatureData& sigdata)
{
    if (sigdata.complete) return true;

    std::vector<valtype> result;
    TxoutType whichType;
    bool solved = SignStep(provider, creator, fromPubKey, result, whichType, SigVersion::BASE, sigdata);
    bool P2SH = false;
    CScript subscript;

    if (solved && whichType == TxoutType::SCRIPTHASH)
    {
        // Solver returns the subscript that needs to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        subscript = CScript(result[0].begin(), result[0].end());
        sigdata.redeem_script = subscript;
        solved = solved && SignStep(provider, creator, subscript, result, whichType, SigVersion::BASE, sigdata) && whichType != TxoutType::SCRIPTHASH;
        P2SH = true;
    }

    if (solved && whichType == TxoutType::WITNESS_V0_KEYHASH)
    {
        CScript witnessscript;
        witnessscript << OP_DUP << OP_HASH160 << ToByteVector(result[0]) << OP_EQUALVERIFY << OP_CHECKSIG;
        TxoutType subType;
        solved = solved && SignStep(provider, creator, witnessscript, result, subType, SigVersion::WITNESS_V0, sigdata);
        sigdata.scriptWitness.stack = result;
        sigdata.witness = true;
        result.clear();
    }
    else if (solved && whichType == TxoutType::WITNESS_V0_SCRIPTHASH)
    {
        CScript witnessscript(result[0].begin(), result[0].end());
        sigdata.witness_script = witnessscript;

        TxoutType subType{TxoutType::NONSTANDARD};
        solved = solved && SignStep(provider, creator, witnessscript, result, subType, SigVersion::WITNESS_V0, sigdata) && subType != TxoutType::SCRIPTHASH && subType != TxoutType::WITNESS_V0_SCRIPTHASH && subType != TxoutType::WITNESS_V0_KEYHASH;

        // If we couldn't find a solution with the legacy satisfier, try satisfying the script using Miniscript.
        // Note we need to check if the result stack is empty before, because it might be used even if the Script
        // isn't fully solved. For instance the CHECKMULTISIG satisfaction in SignStep() pushes partial signatures
        // and the extractor relies on this behaviour to combine witnesses.
        if (!solved && result.empty()) {
            WshSatisfier ms_satisfier{provider, sigdata, creator, witnessscript};
            const auto ms = miniscript::FromScript(witnessscript, ms_satisfier);
            solved = ms && ms->Satisfy(ms_satisfier, result) == miniscript::Availability::YES;
        }
        result.emplace_back(witnessscript.begin(), witnessscript.end());

        sigdata.scriptWitness.stack = result;
        sigdata.witness = true;
        result.clear();
    }
    if (!sigdata.witness) sigdata.scriptWitness.stack.clear();
    if (P2SH) {
        result.emplace_back(subscript.begin(), subscript.end());
    }
    sigdata.scriptSig = PushAll(result);

    // Test solution
    sigdata.complete = solved && VerifyScript(sigdata.scriptSig, fromPubKey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker());
    return sigdata.complete;
}

namespace {
class SignatureExtractorChecker final : public DeferringSignatureChecker
{
private:
    SignatureData& sigdata;

public:
    SignatureExtractorChecker(SignatureData& sigdata, BaseSignatureChecker& checker) : DeferringSignatureChecker(checker), sigdata(sigdata) {}

    bool CheckPostQuantumSignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override
    {
        if (m_checker.CheckPostQuantumSignature(scriptSig, vchPubKey, scriptCode, sigversion)) {
            CPubKey pubkey(vchPubKey);
            sigdata.signatures.emplace(pubkey.GetID(), SigPair(pubkey, scriptSig));
            return true;
        }
        return false;
    }
};

struct Stacks
{
    std::vector<valtype> script;
    std::vector<valtype> witness;

    Stacks() = delete;
    Stacks(const Stacks&) = delete;
    explicit Stacks(const SignatureData& data) : witness(data.scriptWitness.stack) {
        EvalScript(script, data.scriptSig, 0, BaseSignatureChecker(), SigVersion::BASE);
    }
};
}

// Extracts signatures and scripts from incomplete scriptSigs. Please do not extend this, use PSBT instead
SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn, const CTxOut& txout)
{
    SignatureData data;
    assert(tx.vin.size() > nIn);
    data.scriptSig = tx.vin[nIn].scriptSig;
    data.scriptWitness = tx.vin[nIn].scriptWitness;
    Stacks stack(data);

    // Get signatures
    MutableTransactionSignatureChecker tx_checker(&tx, nIn, txout.nValue, MissingDataBehavior::FAIL);
    SignatureExtractorChecker extractor_checker(data, tx_checker);
    if (VerifyScript(data.scriptSig, txout.scriptPubKey, &data.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, extractor_checker)) {
        data.complete = true;
        return data;
    }

    // Get scripts
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType script_type = Solver(txout.scriptPubKey, solutions);
    SigVersion sigversion = SigVersion::BASE;
    CScript next_script = txout.scriptPubKey;

    if (script_type == TxoutType::SCRIPTHASH && !stack.script.empty() && !stack.script.back().empty()) {
        // Get the redeemScript
        CScript redeem_script(stack.script.back().begin(), stack.script.back().end());
        data.redeem_script = redeem_script;
        next_script = std::move(redeem_script);

        // Get redeemScript type
        script_type = Solver(next_script, solutions);
        stack.script.pop_back();
    }
    if (script_type == TxoutType::WITNESS_V0_SCRIPTHASH && !stack.witness.empty() && !stack.witness.back().empty()) {
        // Get the witnessScript
        CScript witness_script(stack.witness.back().begin(), stack.witness.back().end());
        data.witness_script = witness_script;
        next_script = std::move(witness_script);

        // Get witnessScript type
        script_type = Solver(next_script, solutions);
        stack.witness.pop_back();
        stack.script = std::move(stack.witness);
        stack.witness.clear();
        sigversion = SigVersion::WITNESS_V0;
    }
    if (script_type == TxoutType::MULTISIG && !stack.script.empty()) {
        // Build a map of pubkey -> signature by matching sigs to pubkeys:
        assert(solutions.size() > 1);
        unsigned int num_pubkeys = solutions.size()-2;
        unsigned int last_success_key = 0;
        for (const valtype& sig : stack.script) {
            for (unsigned int i = last_success_key; i < num_pubkeys; ++i) {
                const valtype& pubkey = solutions[i+1];
                // We either have a signature for this pubkey, or we have found a signature and it is valid
                if (data.signatures.count(CPubKey(pubkey).GetID()) || extractor_checker.CheckPostQuantumSignature(sig, pubkey, next_script, sigversion)) {
                    last_success_key = i + 1;
                    break;
                }
            }
        }
    }

    return data;
}

void UpdateInput(CTxIn& input, const SignatureData& data)
{
    input.scriptSig = data.scriptSig;
    input.scriptWitness = data.scriptWitness;
}

void SignatureData::MergeSignatureData(SignatureData sigdata)
{
    if (complete) return;
    if (sigdata.complete) {
        *this = std::move(sigdata);
        return;
    }
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    signatures.insert(std::make_move_iterator(sigdata.signatures.begin()), std::make_move_iterator(sigdata.signatures.end()));
}

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker final : public BaseSignatureChecker
{
public:
    DummySignatureChecker() = default;
    bool CheckPostQuantumSignature(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override { return sig.size() != 0; }
    bool CheckLockTime(const CScriptNum& nLockTime) const override { return true; }
    bool CheckSequence(const CScriptNum& nSequence) const override { return true; }
};
}

const BaseSignatureChecker& DUMMY_CHECKER = DummySignatureChecker();

namespace {
class DummySignatureCreator final : public BaseSignatureCreator {
private:
    char m_r_len = 32;
    char m_s_len = 32;
public:
    DummySignatureCreator(char r_len, char s_len) : m_r_len(r_len), m_s_len(s_len) {}
    const BaseSignatureChecker& Checker() const override { return DUMMY_CHECKER; }
    bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const override
    {
        // Create a dummy signature that is a valid DER-encoding
        vchSig.assign(m_r_len + m_s_len + 7, '\000');
        vchSig[0] = 0x30;
        vchSig[1] = m_r_len + m_s_len + 4;
        vchSig[2] = 0x02;
        vchSig[3] = m_r_len;
        vchSig[4] = 0x01;
        vchSig[4 + m_r_len] = 0x02;
        vchSig[5 + m_r_len] = m_s_len;
        vchSig[6 + m_r_len] = 0x01;
        vchSig[6 + m_r_len + m_s_len] = SIGHASH_ALL;
        return true;
    }
};

}

const BaseSignatureCreator& DUMMY_SIGNATURE_CREATOR = DummySignatureCreator(32, 32);
const BaseSignatureCreator& DUMMY_MAXIMUM_SIGNATURE_CREATOR = DummySignatureCreator(33, 32);

bool IsSegWitOutput(const SigningProvider& provider, const CScript& script)
{
    int version;
    valtype program;
    if (script.IsWitnessProgram(version, program)) return true;
    if (script.IsPayToScriptHash()) {
        std::vector<valtype> solutions;
        auto whichtype = Solver(script, solutions);
        if (whichtype == TxoutType::SCRIPTHASH) {
            auto h160 = uint160(solutions[0]);
            CScript subscript;
            if (provider.GetCScript(CScriptID{h160}, subscript)) {
                if (subscript.IsWitnessProgram(version, program)) return true;
            }
        }
    }
    return false;
}

bool SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, int nHashType, std::map<int, bilingual_str>& input_errors)
{
    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mtx);

    PrecomputedTransactionData txdata;
    std::vector<CTxOut> spent_outputs;
    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        CTxIn& txin = mtx.vin[i];
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent()) {
            txdata.Init(txConst, /*spent_outputs=*/{}, /*force=*/true);
            break;
        } else {
            spent_outputs.emplace_back(coin->second.out.nValue, coin->second.out.scriptPubKey);
        }
    }
    if (spent_outputs.size() == mtx.vin.size()) {
        txdata.Init(txConst, std::move(spent_outputs), true);
    }

    // Sign what we can:
    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        CTxIn& txin = mtx.vin[i];
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent()) {
            input_errors[i] = _("Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = coin->second.out.scriptPubKey;
        const CAmount& amount = coin->second.out.nValue;

        SignatureData sigdata = DataFromTransaction(mtx, i, coin->second.out);
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mtx.vout.size())) {
            ProduceSignature(*keystore, MutableTransactionSignatureCreator(mtx, i, amount, &txdata, nHashType), prevPubKey, sigdata);
        }

        UpdateInput(txin, sigdata);

        // amount must be specified for valid segwit signature
        if (amount == MAX_MONEY && !txin.scriptWitness.IsNull()) {
            input_errors[i] = _("Missing amount");
            continue;
        }

        ScriptError serror = SCRIPT_ERR_OK;
        if (!sigdata.complete && !VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, amount, txdata, MissingDataBehavior::FAIL), &serror)) {
            if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                // Unable to sign input and verification failed (possible attempt to partially sign).
                input_errors[i] = Untranslated("Unable to sign input, invalid stack size (possibly missing key)");
            } else if (serror == SCRIPT_ERR_SIG_NULLFAIL) {
                // Verification failed (possibly due to insufficient signatures).
                input_errors[i] = Untranslated("CHECK(MULTI)SIG failing with non-zero signature (possibly need more signatures)");
            } else {
                input_errors[i] = Untranslated(ScriptErrorString(serror));
            }
        } else {
            // If this input succeeds, make sure there is no error set for it
            input_errors.erase(i);
        }
    }
    return input_errors.empty();
}
