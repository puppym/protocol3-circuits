#ifndef _ACCOUNTGADGETS_H_
#define _ACCOUNTGADGETS_H_

#include "../Utils/Constants.h"
#include "../Utils/Data.h"

#include "MerkleTree.h"

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "gadgets/merkle_tree.hpp"
#include "gadgets/poseidon.hpp"

using namespace ethsnarks;

namespace Loopring
{

struct AccountState
{
    VariableT publicKeyX;
    VariableT publicKeyY;
    VariableT nonce;
    VariableT balancesRoot;
};

class AccountGadget : public GadgetT
{
public:
    const jubjub::VariablePointT publicKey;
    VariableT nonce;
    VariableT balancesRoot;

    AccountGadget(
        ProtoboardT& pb,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        publicKey(pb, FMT(prefix, ".publicKey")),
        nonce(make_variable(pb, FMT(prefix, ".nonce"))),
        balancesRoot(make_variable(pb, FMT(prefix, ".balancesRoot")))
    {

    }

    void generate_r1cs_witness(const Account& account)
    {
        pb.val(publicKey.x) = account.publicKey.x;
        pb.val(publicKey.y) = account.publicKey.y;
        pb.val(nonce) = account.nonce;
        pb.val(balancesRoot) = account.balancesRoot;
    }
};

class UpdateAccountGadget : public GadgetT
{
public:
    HashAccountLeaf leafBefore;
    HashAccountLeaf leafAfter;

    const VariableArrayT proof;
    MerklePathCheckT proofVerifierBefore;
    MerklePathT rootCalculatorAfter;

    UpdateAccountGadget(
        ProtoboardT& pb,
        const VariableT& merkleRoot,
        const VariableArrayT& address,
        const AccountState& before,
        const AccountState& after,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        leafBefore(pb, var_array({before.publicKeyX, before.publicKeyY, before.nonce, before.balancesRoot}), FMT(prefix, ".leafBefore")),
        leafAfter(pb, var_array({after.publicKeyX, after.publicKeyY, after.nonce, after.balancesRoot}), FMT(prefix, ".leafAfter")),

        proof(make_var_array(pb, TREE_DEPTH_ACCOUNTS * 3, FMT(prefix, ".proof"))),
        proofVerifierBefore(pb, TREE_DEPTH_ACCOUNTS, address, leafBefore.result(), merkleRoot, proof, FMT(prefix, ".pathBefore")),
        rootCalculatorAfter(pb, TREE_DEPTH_ACCOUNTS, address, leafAfter.result(), proof, FMT(prefix, ".pathAfter"))
    {

    }

    void generate_r1cs_witness(const Proof& _proof)
    {
        leafBefore.generate_r1cs_witness();
        leafAfter.generate_r1cs_witness();

        proof.fill_with_field_elements(pb, _proof.data);
        proofVerifierBefore.generate_r1cs_witness();
        rootCalculatorAfter.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        leafBefore.generate_r1cs_constraints();
        leafAfter.generate_r1cs_constraints();

        proofVerifierBefore.generate_r1cs_constraints();
        rootCalculatorAfter.generate_r1cs_constraints();
    }

    const VariableT& result() const
    {
        return rootCalculatorAfter.result();
    }
};

struct BalanceState
{
    VariableT balance;
    VariableT tradingHistory;
};

class BalanceGadget : public GadgetT
{
public:
    // balnace 
    VariableT balance;
    // tradingHistoryRoot
    VariableT tradingHistory;

    BalanceGadget(
        ProtoboardT& pb,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        balance(make_variable(pb, FMT(prefix, ".balance"))),
        tradingHistory(make_variable(pb, FMT(prefix, ".tradingHistory")))
    {

    }

    void generate_r1cs_witness(const BalanceLeaf& balanceLeaf)
    {
        pb.val(balance) = balanceLeaf.balance;
        pb.val(tradingHistory) = balanceLeaf.tradingHistoryRoot;
    }
};

class UpdateBalanceGadget : public GadgetT
{
public:
    // 
    HashBalanceLeaf leafBefore;
    HashBalanceLeaf leafAfter;

    // 证明路径
    const VariableArrayT proof;
    // Merkle路径验证器
    MerklePathCheckT proofVerifierBefore;
    // Merkle新根节点计算
    MerklePathT rootCalculatorAfter;

    UpdateBalanceGadget(
        ProtoboardT& pb,
        const VariableT& merkleRoot,
        const VariableArrayT& tokenID,
        const BalanceState before,
        const BalanceState after,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        leafBefore(pb, var_array({before.balance, before.tradingHistory}), FMT(prefix, ".leafBefore")),
        leafAfter(pb, var_array({after.balance, after.tradingHistory}), FMT(prefix, ".leafAfter")),

        proof(make_var_array(pb, TREE_DEPTH_TOKENS * 3, FMT(prefix, ".proof"))),
        // 之前的叶子节点加上路径得到之前的根节点，与期望的根节点验证，确认之前状态的正确性
        // 验证之前的状态
        proofVerifierBefore(pb, TREE_DEPTH_TOKENS, tokenID, leafBefore.result(), merkleRoot, proof, FMT(prefix, ".pathBefore")),
        // 之后的叶子节点加上路径得到之后的根节点，得到状态修改之后的根节点
        // 获取叶子节点修改之后的结果
        rootCalculatorAfter(pb, TREE_DEPTH_TOKENS, tokenID, leafAfter.result(), proof, FMT(prefix, ".pathAfter"))
    {

    }

    void generate_r1cs_witness(const Proof& _proof)
    {
        leafBefore.generate_r1cs_witness();
        leafAfter.generate_r1cs_witness();

        proof.fill_with_field_elements(pb, _proof.data);
        proofVerifierBefore.generate_r1cs_witness();
        rootCalculatorAfter.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        leafBefore.generate_r1cs_constraints();
        leafAfter.generate_r1cs_constraints();

        proofVerifierBefore.generate_r1cs_constraints();
        rootCalculatorAfter.generate_r1cs_constraints();
    }

    const VariableT& result() const
    {
        return rootCalculatorAfter.result();
    }
};

}

#endif
