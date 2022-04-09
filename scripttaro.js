verify_asset_file_proof(file_proof []byte, genesis_outpoint OutPoint, 
    assetID [32]byte) -> bool

    file_sum = read(num_bytes=32, file_proof)
    sha_sum = sh256(drop(bytes_to_drop=32, file_proof))
    if file_sum != sha_sum:
        return false

    genesis_outpoint, prev_outpoint = None
    file_reader = new_bytes_reader(file_proof)
    while file_reader.len() != 0:
        proof_block = parse_proof_block(file_reader)

        if genesis_outpoint is None:
            genesis_outpoint = proof_block.previous_outpoint

        txn = proof_block.txn
        if genesis_outpoint is not None:
           if !spends_prev_out(txn):
               return false

        if !verify_merkle_proof(
            proof_block.block_header, proof_block.merkle_inclusion_proof, txn,
        ):
            return false

        proof_tlv_map = proof_block.tlv_map

        if len(txn.outputs) < proof_tlv_map.asset_output_pos:
            return false

        if !verify_asset_tree_proof(
            txn, proof_tlv_map.taro_asset_leaf, proof_tlv_map.asset_leaf_proof,
        ):
            return false

        if !verify_taro_state_transition(proof_tlv_map.taro_asset_leaf):
            return false

        if proof_tlv_map.split_commitment_opening is not None:
            if !verify_split_commitment(
                proof_tlv_map.taro_asset_leaf, 
                proof_tlv_map.split_commitment_opening,
            ):
                return false

    return true
