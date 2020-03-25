// Copyright 2014 The go-auc Authors
// This file is part of the go-auc library.
//
// The go-auc library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-auc library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-auc library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/auchain/auchain/crypto"
	"github.com/auchain/auchain/p2p/enode"
	"math/big"
	"strings"

	"github.com/auchain/auchain/common"
	"github.com/auchain/auchain/common/hexutil"
	"github.com/auchain/auchain/common/math"
	"github.com/auchain/auchain/core/rawdb"
	"github.com/auchain/auchain/core/state"
	"github.com/auchain/auchain/core/types"
	"github.com/auchain/auchain/ethdb"
	"github.com/auchain/auchain/log"
	"github.com/auchain/auchain/params"
	"github.com/auchain/auchain/rlp"
)

//go:generate gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go
//go:generate gencodec -type GenesisAccount -field-override genesisAccountMarshaling -out gen_genesis_account.go

var errGenesisNoConfig = errors.New("genesis has no chain configuration")

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type Genesis struct {
	Config     *params.ChainConfig `json:"config"`
	Nonce      uint64              `json:"nonce"`
	Timestamp  uint64              `json:"timestamp"`
	ExtraData  []byte              `json:"extraData"`
	GasLimit   uint64              `json:"gasLimit"   gencodec:"required"`
	Difficulty *big.Int            `json:"difficulty" gencodec:"required"`
	Mixhash    common.Hash         `json:"mixHash"`
	Coinbase   common.Address      `json:"coinbase"`
	StateRoot  common.Hash         `json:"stateRoot"`
	Alloc      GenesisAlloc        `json:"alloc"      gencodec:"required"`

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number     uint64      `json:"number"`
	GasUsed    uint64      `json:"gasUsed"`
	ParentHash common.Hash `json:"parentHash"`
}

// GenesisAlloc specifies the initial state that is part of the genesis block.
type GenesisAlloc map[common.Address]GenesisAccount

func (ga *GenesisAlloc) UnmarshalJSON(data []byte) error {
	m := make(map[common.UnprefixedAddress]GenesisAccount)
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*ga = make(GenesisAlloc)
	for addr, a := range m {
		(*ga)[common.Address(addr)] = a
	}
	return nil
}

// GenesisAccount is an account in the state of the genesis block.
type GenesisAccount struct {
	Code       []byte                      `json:"code,omitempty"`
	Storage    map[common.Hash]common.Hash `json:"storage,omitempty"`
	Balance    *big.Int                    `json:"balance" gencodec:"required"`
	Nonce      uint64                      `json:"nonce,omitempty"`
	PrivateKey []byte                      `json:"secretKey,omitempty"` // for tests
}

// field type overrides for gencodec
type genesisSpecMarshaling struct {
	Nonce      math.HexOrDecimal64
	Timestamp  math.HexOrDecimal64
	ExtraData  hexutil.Bytes
	GasLimit   math.HexOrDecimal64
	GasUsed    math.HexOrDecimal64
	Number     math.HexOrDecimal64
	Difficulty *math.HexOrDecimal256
	Alloc      map[common.UnprefixedAddress]GenesisAccount
}

type genesisAccountMarshaling struct {
	Code       hexutil.Bytes
	Balance    *math.HexOrDecimal256
	Nonce      math.HexOrDecimal64
	Storage    map[storageJSON]storageJSON
	PrivateKey hexutil.Bytes
}

// storageJSON represents a 256 bit byte array, but allows less than 256 bits when
// unmarshaling from hex.
type storageJSON common.Hash

func (h *storageJSON) UnmarshalText(text []byte) error {
	text = bytes.TrimPrefix(text, []byte("0x"))
	if len(text) > 64 {
		return fmt.Errorf("too many hex characters in storage key/value %q", text)
	}
	offset := len(h) - len(text)/2 // pad on the left
	if _, err := hex.Decode(h[offset:], text); err != nil {
		fmt.Println(err)
		return fmt.Errorf("invalid hex storage key/value %q", text)
	}
	return nil
}

func (h storageJSON) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type GenesisMismatchError struct {
	Stored, New common.Hash
}

func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database already contains an incompatible genesis block (have %x, new %x)", e.Stored[:8], e.New[:8])
}

// SetupGenesisBlock writes or updates the genesis block in db.
// The block that will be used is:
//
//                          genesis == nil       genesis != nil
//                       +------------------------------------------
//     db has no genesis |  main-net default  |  genesis
//     db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func SetupGenesisBlock(db ethdb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.CircumChainConfig, common.Hash{}, errGenesisNoConfig
	}
	// Just commit the new block if there is no stored genesis block.
	stored := rawdb.ReadCanonicalHash(db, params.GenesisBlockNumber)
	if (stored == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		block, err := genesis.Commit(db)
		return genesis.Config, block.Hash(), err
	}
	// Check whether the genesis block is already written.
	if genesis != nil {
		hash := genesis.ToBlock(nil).Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
	}
	// Get the existing chain configuration.
	newcfg := genesis.configOrDefault(stored)
	storedcfg := rawdb.ReadChainConfig(db, stored)
	if storedcfg == nil {
		log.Warn("Found genesis block without chain config")
		rawdb.WriteChainConfig(db, stored, newcfg)

		return newcfg, stored, nil
	}
	// Special case: don't change the existing config of a non-mainnet chain if no new
	// config is supplied. These chains would get AllProtocolChanges (and a compat error)
	// if we just continued here.
	if genesis == nil && stored != params.MainnetGenesisHash {
		return storedcfg, stored, nil
	}
	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	height := rawdb.ReadHeaderNumber(db, rawdb.ReadHeadHeaderHash(db))
	if height == nil {

		return newcfg, stored, fmt.Errorf("missing block number for head header hash")
	}
	compatErr := storedcfg.CheckCompatible(newcfg, *height)
	if compatErr != nil && *height != 0 && compatErr.RewindTo != 0 {

		return newcfg, stored, compatErr
	}
	rawdb.WriteChainConfig(db, stored, newcfg)
	return newcfg, stored, nil
}

func (g *Genesis) configOrDefault(ghash common.Hash) *params.ChainConfig {
	switch {
	case g != nil:
		return g.Config
	default:
		return params.CircumChainConfig
	}
}

// ToBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *Genesis) ToBlock(db ethdb.Database) *types.Block {
	if db == nil {
		db = ethdb.NewMemDatabase()
	}

	statedb, _ := state.New(g.StateRoot, state.NewDatabase(db))
	for addr, account := range g.Alloc {
		statedb.AddBalance(addr, account.Balance, big.NewInt(1))
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	root := statedb.IntermediateRoot(false)

	head := &types.Header{
		Number:     new(big.Int).SetUint64(g.Number),
		Nonce:      types.EncodeNonce(g.Nonce),
		Time:       g.Timestamp,
		ParentHash: g.ParentHash,
		Extra:      g.ExtraData,
		GasLimit:   g.GasLimit,
		GasUsed:    g.GasUsed,
		Difficulty: g.Difficulty,
		MixDigest:  g.Mixhash,
		Coinbase:   g.Coinbase,
		Root:       root,
	}
	if g.GasLimit == 0 {
		head.GasLimit = params.GenesisGasLimit
	}
	if g.Difficulty == nil {
		head.Difficulty = params.GenesisDifficulty
	}
	statedb.Commit(false)
	statedb.Database().TrieDB().Commit(root, false)
	block := types.NewBlock(head, nil, nil, nil)

	return block
}

// Commit writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) Commit(db ethdb.Database) (*types.Block, error) {
	block := g.ToBlock(db)
	if block.NumberU64() != params.GenesisBlockNumber {
		return nil, fmt.Errorf("can't commit genesis block with number != %d", params.GenesisBlockNumber)
	}
	rawdb.WriteTd(db, block.Hash(), block.NumberU64(), g.Difficulty)
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())

	config := g.Config
	if config == nil {
		config = params.AllEthashProtocolChanges
	}
	rawdb.WriteChainConfig(db, block.Hash(), config)
	return block, nil
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustCommit(db ethdb.Database) *types.Block {
	block, err := g.Commit(db)
	if err != nil {
		panic(err)
	}
	return block
}

// GenesisBlockForTesting creates and writes a block in which addr has the given wei balance.
func GenesisBlockForTesting(db ethdb.Database, addr common.Address, balance *big.Int) *types.Block {
	g := Genesis{Alloc: GenesisAlloc{addr: {Balance: balance}}}
	return g.MustCommit(db)
}

// DefaultGenesisBlock returns the Ethereum main net genesis block.
func DefaultGenesisBlock() *Genesis {
	alloc := decodePrealloc(mainnetAllocData)
	alloc[common.BytesToAddress(params.MasterndeContractAddress.Bytes())] = masternodeContractAccount(params.MainnetMasternodes)
	alloc[common.HexToAddress("0xeD420cfD2252231CD4DA070423E38eB8ae32e52C")] = GenesisAccount{
		Balance: new(big.Int).Mul(big.NewInt(21e+9), big.NewInt(1e+15)),
	}
	//alloc[common.HexToAddress("0xe1f99A3bA242d01EA0001B77Cd143e595b8743aC")] = GenesisAccount{
	//	Balance: new(big.Int).Mul(big.NewInt(21e+9), big.NewInt(1e+15)),
	//}
	config := params.CircumChainConfig
	var witnesses []string
	for _, n := range params.MainnetMasternodes {
		node := enode.MustParseV4(n)
		pubkey := node.Pubkey()
		addr := crypto.PubkeyToAddress(*pubkey)
		if _, ok := alloc[addr]; !ok {
			alloc[addr] = GenesisAccount{
				Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(1e+16)),
			}
		}
		xBytes := pubkey.X.Bytes()
		var x [32]byte
		copy(x[32-len(xBytes):], xBytes[:])
		id1 := common.BytesToHash(x[:])
		id := fmt.Sprintf("%x", id1[:8])
		witnesses = append(witnesses, id)
	}
	config.Circum.Witnesses = witnesses
	return &Genesis{
		Config:     config,
		Nonce:      1,
		Timestamp:  1583712800,
		GasLimit:   10000000,
		Difficulty: big.NewInt(1),
		Alloc:      alloc,
		Number:     params.GenesisBlockNumber,
	}
}

// DefaultTestnetGenesisBlock returns the Ropsten network genesis block.
func DefaultTestnetGenesisBlock() *Genesis {
	alloc := decodePrealloc(testnetAllocData)
	alloc[common.BytesToAddress(params.MasterndeContractAddress.Bytes())] = masternodeContractAccount(params.TestnetMasternodes)
	alloc[common.HexToAddress("0x4b961Cc393e08DF94F70Cad88142B9962186FfD1")] = GenesisAccount{
		Balance: new(big.Int).Mul(big.NewInt(1e+11), big.NewInt(1e+15)),
	}
	config := params.TestnetChainConfig
	var witnesses []string
	for _, n := range params.TestnetMasternodes {
		node := enode.MustParseV4(n)
		pubkey := node.Pubkey()
		//addr := crypto.PubkeyToAddress(*pubkey)
		//if _, ok := alloc[addr]; !ok {
		//	alloc[addr] = GenesisAccount{
		//		Balance: new(big.Int).Mul(big.NewInt(1e+16), big.NewInt(1e+15)),
		//	}
		//}
		xBytes := pubkey.X.Bytes()
		var x [32]byte
		copy(x[32-len(xBytes):], xBytes[:])
		id1 := common.BytesToHash(x[:])
		id := fmt.Sprintf("%x", id1[:8])
		witnesses = append(witnesses, id)
	}
	config.Circum.Witnesses = witnesses
	return &Genesis{
		Config:     config,
		Nonce:      66,
		Timestamp:  1531551970,
		ExtraData:  hexutil.MustDecode("0x3535353535353535353535353535353535353535353535353535353535353535"),
		GasLimit:   16777216,
		Difficulty: big.NewInt(1048576),
		Alloc:      alloc,
	}
}

// DefaultRinkebyGenesisBlock returns the Rinkeby network genesis block.
func DefaultRinkebyGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.RinkebyChainConfig,
		Timestamp:  1492009146,
		ExtraData:  hexutil.MustDecode("0x52657370656374206d7920617574686f7269746168207e452e436172746d616e42eb768f2244c8811c63729a21a3569731535f067ffc57839b00206d1ad20c69a1981b489f772031b279182d99e65703f0076e4812653aab85fca0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      decodePrealloc(rinkebyAllocData),
	}
}

// DefaultGoerliGenesisBlock returns the Görli network genesis block.
func DefaultGoerliGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.GoerliChainConfig,
		Timestamp:  1548854791,
		ExtraData:  hexutil.MustDecode("0x22466c6578692069732061207468696e6722202d204166726900000000000000e0a2bd4258d2768837baa26a28fe71dc079f84c70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   10485760,
		Difficulty: big.NewInt(1),
		// Alloc:      decodePrealloc(goerliAllocData),
	}
}

// DeveloperGenesisBlock returns the 'geth --dev' genesis block. Note, this must
// be seeded with the
func DeveloperGenesisBlock(period uint64, faucet common.Address) *Genesis {
	// Override the default period to the user requested one
	config := *params.AllCliqueProtocolChanges
	config.Clique.Period = period

	// Assemble and return the genesis with the precompiles and faucet pre-funded
	return &Genesis{
		Config:     &config,
		ExtraData:  append(append(make([]byte, 32), faucet[:]...), make([]byte, 65)...),
		GasLimit:   6283185,
		Difficulty: big.NewInt(1),
		Alloc: map[common.Address]GenesisAccount{
			common.BytesToAddress([]byte{1}): {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}): {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}): {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}): {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}): {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}): {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}): {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}): {Balance: big.NewInt(1)}, // ECPairing
			faucet:                           {Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))},
		},
	}
}

func decodePrealloc(data string) GenesisAlloc {
	var p []struct{ Addr, Balance *big.Int }
	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		panic(err)
	}
	ga := make(GenesisAlloc, len(p))
	for _, account := range p {
		ga[common.BigToAddress(account.Addr)] = GenesisAccount{Balance: account.Balance}
	}
	return ga
}

func masternodeContractAccount(masternodes []string) GenesisAccount {
	data := make(map[common.Hash]common.Hash)

	data[common.HexToHash("0x737623345846fae5a1129d803037fa8fd3dfd54f114e43e403b22f4369e3ae94")] = common.HexToHash("0xa2bc05720344a278d5c10e63ff24221e7cb4e73d4817fad74f6c9d1bc31e0d1c")
	data[common.HexToHash("0x18cd7397731ddab51183213b754d813b316f6c82f1ef033eb7d91a632c7b2417")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x741fd89f11df0112dc19809e11522dbc03a9cbf3f9f2da933cb745ec9f1687a8")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x06c1a148fbb2b0f6a5b1ef9b5f5e76ff059b25b152ac60264e0a2d59df083222")] = common.HexToHash("0xf83e59209190dda1684b0e49ff289063cbfca458d48093d65692870e2e173d18")
	data[common.HexToHash("0x802cceb9ff1d62c4aad643e8b314be190f6bbbb0e50e0b63b5a1ac95e48f771c")] = common.HexToHash("0x000000000000000000000000000000000000000000000000ef86404f30dcc41a")
	data[common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000")] = common.HexToHash("0x0000000000000000000000000000000000000000000000009cbf4d4cd15c7d94")
	data[common.HexToHash("0x281e7f87f3d6aa47e399cb08406605021a28c1be7226e3506d0dae792b7f338c")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0xdd666736a8e576f4beeacd7f3cdef5e96f2319a92319c88ada1f772db741a08c")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x8e5b0e94df2f89afa53a46918f387ff6f72fd501b26ebd1185b4f4dd996b4d51")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x87250d5b027f1bb5bf4027d838685dca1727394f9d46f567d5926405d649adf0")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x2aa0b60f7b7e0618f2f4ad7d11e245c92f06ca3b7e881e4cc541ef5fab27a7f8")] = common.HexToHash("0x0000000000000000000000000000000000000000000000009cbf4d4cd15c7d94")
	data[common.HexToHash("0x72f8edce16b1d47f1c34abf48ea3db8337721380789f3d9ecdbce854f08a674a")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0xfa0d6d0aaecb254018bfe12219afd4cc6f189d72f9db340053d2d60032944b50")] = common.HexToHash("0xfe55b5cbb8c2e5c28cc183fbe1efda7768f1d301fb95e9db61a0d8c4e94e5dee")
	data[common.HexToHash("0xdd666736a8e576f4beeacd7f3cdef5e96f2319a92319c88ada1f772db741a08e")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0xfa0d6d0aaecb254018bfe12219afd4cc6f189d72f9db340053d2d60032944b52")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x737623345846fae5a1129d803037fa8fd3dfd54f114e43e403b22f4369e3ae95")] = common.HexToHash("0x80bca2ee52c99800ce6396d6094e87604f8e82f2b8a768e5141bb8237f001412")
	data[common.HexToHash("0x1a99b15dcf9a66ce173776cff987a204d07aa1b732c96b75507fee8dcf0bcf26")] = common.HexToHash("0x0000000000000000000000000000000000000000000000001673b3e059756835")
	data[common.HexToHash("0xde9331f9f326a1748b52dae5ca6126e7a66c0858454b7fe669618a8e05a9a36e")] = common.HexToHash("0x7e061aeb155f090b2348df549a4c13a1f0652c3bb1c69644180fe6dfaa1d9c48")
	data[common.HexToHash("0xde9331f9f326a1748b52dae5ca6126e7a66c0858454b7fe669618a8e05a9a372")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x72f8edce16b1d47f1c34abf48ea3db8337721380789f3d9ecdbce854f08a6747")] = common.HexToHash("0x00000000000000000000000000000000e48d8ee2baf2b2dbe88e2550f5f31ea3")
	data[common.HexToHash("0xbf766c9947ee85772af554948694e6fa3526aff0345d5855c7bf2881c91070c9")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x33913de43aa2b09c194649e46f7617620ecc868cecedd41cf0445548438dffcc")] = common.HexToHash("0xef86404f30dcc41a62dcb45b1047d356726dcd138d5f3cd788d00f6de7fc2353")
	data[common.HexToHash("0x36c39072f7fae573c3e0007f14a68ed0324710083fa87e55ead0adbb24db5ebe")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x6a59d4286b75d6c92c977a830b1f8f7fc5c6e024a14a4342994e8c64559af6fe")] = common.HexToHash("0x000000000000000000000000000000000000000000000000ee532ce19fdc0dad")
	data[common.HexToHash("0x36c10275e70689eb8e465ff89dfc95571f5c17baa4caf528b6b021eecde76995")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x93d8c5336a6367fc18b4e190f7e8047da729f57e02dd628711673a07125b37aa")] = common.HexToHash("0x0000000000000000000000000000000000000000000000008274c2f94b82a9a3")
	data[common.HexToHash("0x776c33b39f89a952c8bf6a5b7c8880a7b546e6004f6e3d36fa63c300dd017031")] = common.HexToHash("0x9cbf4d4cd15c7d9498bae6e7473b9b901564cf1665790edd32f5024abdd32887")
	data[common.HexToHash("0x2d1b393b912fb80d6d80ff8762610fff8c6e589828b1039d0bdda5876464311a")] = common.HexToHash("0x000000000000000000000000000000000000000000000000e88e2550f5f31ea3")
	data[common.HexToHash("0x838cd774569511bbf990571ebc8799cdc392a8f8ea639a1a5b9db04eec1f99e4")] = common.HexToHash("0x000000000000000000000000000000000000000000000000f68e117541c57bd0")
	data[common.HexToHash("0x8e5b0e94df2f89afa53a46918f387ff6f72fd501b26ebd1185b4f4dd996b4d4d")] = common.HexToHash("0xa835081d57529a37fa073ffa68cd6c9e6a94be5e219262f477de7abc88c9dae5")
	data[common.HexToHash("0x8e5b0e94df2f89afa53a46918f387ff6f72fd501b26ebd1185b4f4dd996b4d4e")] = common.HexToHash("0x1554de017be1239ba3df819fbe02f772dc4d163a465e3ff437271f7cbc6774a0")
	data[common.HexToHash("0xde9331f9f326a1748b52dae5ca6126e7a66c0858454b7fe669618a8e05a9a36f")] = common.HexToHash("0x27334bd63ef1d4f7274c45a955c0c011aa4b433f5becbae3754c1c079684d75d")
	data[common.HexToHash("0x06c1a148fbb2b0f6a5b1ef9b5f5e76ff059b25b152ac60264e0a2d59df083221")] = common.HexToHash("0x8274c2f94b82a9a37fbc38f8bd3523a5d14a1f441645ffde7f0c4cdf27873625")
	data[common.HexToHash("0xe212bf5e26869d4ad1f987da3d72c6c5e040d863543f1e82d23832d2ec7d27c3")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0xfa0d6d0aaecb254018bfe12219afd4cc6f189d72f9db340053d2d60032944b53")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x741fd89f11df0112dc19809e11522dbc03a9cbf3f9f2da933cb745ec9f1687aa")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x06c1a148fbb2b0f6a5b1ef9b5f5e76ff059b25b152ac60264e0a2d59df083224")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x36c10275e70689eb8e465ff89dfc95571f5c17baa4caf528b6b021eecde76992")] = common.HexToHash("0x00000000000000000000000000000000ef86404f30dcc41a8158855a700b4d18")
	data[common.HexToHash("0x18dd1b5802a0c0f8f465a58b398dd1e3180808ccfecf57628325749767611976")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x72f8edce16b1d47f1c34abf48ea3db8337721380789f3d9ecdbce854f08a6748")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0xe212bf5e26869d4ad1f987da3d72c6c5e040d863543f1e82d23832d2ec7d27c5")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x36c10275e70689eb8e465ff89dfc95571f5c17baa4caf528b6b021eecde76990")] = common.HexToHash("0x93b96fe81a6929f88c4b9ae641e6ee8955641008c543cf8395602ce0e3e77eac")
	data[common.HexToHash("0x87250d5b027f1bb5bf4027d838685dca1727394f9d46f567d5926405d649adf1")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x36c10275e70689eb8e465ff89dfc95571f5c17baa4caf528b6b021eecde76991")] = common.HexToHash("0xbd85652d818f4849843ca1dbe9b6fab7fd370e778bd252134964cb99a1512086")
	data[common.HexToHash("0x68ff259936964d472fd8f07010a3bc1a732939d1e147b7017b022b47c88ca008")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x18cd7397731ddab51183213b754d813b316f6c82f1ef033eb7d91a632c7b2414")] = common.HexToHash("0x00000000000000000000000000000000a835081d57529a37a2bc05720344a278")
	data[common.HexToHash("0x9180dd97c561eea043b8179d7c3c45644f1de4cc4f224e1c035c1d4e508df9fb")] = common.HexToHash("0x000000000000000000000000000000000000000000000000f715b137c5c795f2")
	data[common.HexToHash("0x06c1a148fbb2b0f6a5b1ef9b5f5e76ff059b25b152ac60264e0a2d59df083225")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x36c39072f7fae573c3e0007f14a68ed0324710083fa87e55ead0adbb24db5ebb")] = common.HexToHash("0xe4ac8bbef9a8a3950db400342b8c04485a7d78101219a979009d29b15e3222ad")
	data[common.HexToHash("0x18dd1b5802a0c0f8f465a58b398dd1e3180808ccfecf57628325749767611974")] = common.HexToHash("0x93122f4d2dc602250ac3f9235646191401e0e144575f688f77fe6dfd63e3b47a")
	data[common.HexToHash("0xbf766c9947ee85772af554948694e6fa3526aff0345d5855c7bf2881c91070ca")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0xcfe65a3eb077155e2524df4dd45db2f98532aed67a08dab5d007f4c2da71a1ca")] = common.HexToHash("0xee532ce19fdc0dad9a30439fc88b76be4b292fc9931762b2fb9b10bb56d8ccdd")
	data[common.HexToHash("0xdd666736a8e576f4beeacd7f3cdef5e96f2319a92319c88ada1f772db741a08d")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x9c19af4ee969c809ee2819c41cc1f64097e40a12c024a4af3284cde3957091c2")] = common.HexToHash("0x000000000000000000000000000000000000000000000000a2bc05720344a278")
	data[common.HexToHash("0x87250d5b027f1bb5bf4027d838685dca1727394f9d46f567d5926405d649adec")] = common.HexToHash("0x8158855a700b4d1827c513cb58dd4366a7bd0e012b3015db25d795568389a2ba")
	data[common.HexToHash("0x281e7f87f3d6aa47e399cb08406605021a28c1be7226e3506d0dae792b7f338a")] = common.HexToHash("0x0000000000000000000000000000000096091973276908f30000000000000000")
	data[common.HexToHash("0xcfe65a3eb077155e2524df4dd45db2f98532aed67a08dab5d007f4c2da71a1cf")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x741fd89f11df0112dc19809e11522dbc03a9cbf3f9f2da933cb745ec9f1687a9")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x33913de43aa2b09c194649e46f7617620ecc868cecedd41cf0445548438dffcf")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x36c39072f7fae573c3e0007f14a68ed0324710083fa87e55ead0adbb24db5ebf")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x281e7f87f3d6aa47e399cb08406605021a28c1be7226e3506d0dae792b7f3389")] = common.HexToHash("0xc2fcc76f032b51e6041cb9694cab9b8f7c7210f0d79114f700e0176ae11fe3ae")
	data[common.HexToHash("0xcfe65a3eb077155e2524df4dd45db2f98532aed67a08dab5d007f4c2da71a1cd")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0xde9331f9f326a1748b52dae5ca6126e7a66c0858454b7fe669618a8e05a9a370")] = common.HexToHash("0x00000000000000000000000000000000b7686156a15ee267a835081d57529a37")
	data[common.HexToHash("0x87250d5b027f1bb5bf4027d838685dca1727394f9d46f567d5926405d649adee")] = common.HexToHash("0x0000000000000000000000000000000093b96fe81a6929f88274c2f94b82a9a3")
	data[common.HexToHash("0x33913de43aa2b09c194649e46f7617620ecc868cecedd41cf0445548438dffd0")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x6070fa949ec65ce4fad9e1606f70ce398e67d803d06f06e0f25552f58ca79b92")] = common.HexToHash("0x000000000000000000000000000000000000000000000000680c8ae2c26696a1")
	data[common.HexToHash("0x776c33b39f89a952c8bf6a5b7c8880a7b546e6004f6e3d36fa63c300dd017035")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0xdd666736a8e576f4beeacd7f3cdef5e96f2319a92319c88ada1f772db741a089")] = common.HexToHash("0xf715b137c5c795f247ca2ef2b1d81f1e7be1d47d0c65ba89ae2e3164e6c340ef")
	data[common.HexToHash("0xf83fa58269927e3ed634e55d3f7197a5aec207f3a6b3d70c8183dc1c9321a84d")] = common.HexToHash("0x000000000000000000000000000000000000000000000000cf717fda95412658")
	data[common.HexToHash("0xcfe65a3eb077155e2524df4dd45db2f98532aed67a08dab5d007f4c2da71a1cb")] = common.HexToHash("0xa2fe81f351533f19b9d563a608a3496a620fca7da8d09c188dc9b4b645452457")
	data[common.HexToHash("0x9c77aea8e544556df2d14dad9000bd6d022fbe44dd9639b33101518b8187e0ce")] = common.HexToHash("0x05f21a129b9c1eb3dbe5763fee6265bf4f5c139e8de11f92af94c5d465626054")
	data[common.HexToHash("0x741fd89f11df0112dc19809e11522dbc03a9cbf3f9f2da933cb745ec9f1687a7")] = common.HexToHash("0x000000000000000000000000000000008274c2f94b82a9a37e061aeb155f090b")
	data[common.HexToHash("0x18dd1b5802a0c0f8f465a58b398dd1e3180808ccfecf57628325749767611975")] = common.HexToHash("0x000000000000000000000000000000009cbf4d4cd15c7d94680c8ae2c26696a1")
	data[common.HexToHash("0x776c33b39f89a952c8bf6a5b7c8880a7b546e6004f6e3d36fa63c300dd017033")] = common.HexToHash("0x000000000000000000000000000000000000000000000000e45ee4072f64a771")
	data[common.HexToHash("0x281e7f87f3d6aa47e399cb08406605021a28c1be7226e3506d0dae792b7f338b")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0xbf766c9947ee85772af554948694e6fa3526aff0345d5855c7bf2881c91070c6")] = common.HexToHash("0x1b576f522147be7269e3268488c07f94dd45832e60bcfef50b00862d1a757008")
	data[common.HexToHash("0x8e5b0e94df2f89afa53a46918f387ff6f72fd501b26ebd1185b4f4dd996b4d4f")] = common.HexToHash("0x000000000000000000000000000000007e061aeb155f090b1673b3e059756835")
	data[common.HexToHash("0x36c39072f7fae573c3e0007f14a68ed0324710083fa87e55ead0adbb24db5ebd")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x68ff259936964d472fd8f07010a3bc1a732939d1e147b7017b022b47c88ca007")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0xe212bf5e26869d4ad1f987da3d72c6c5e040d863543f1e82d23832d2ec7d27c2")] = common.HexToHash("0x000000000000000000000000000000001b576f522147be72e48d8ee2baf2b2db")
	data[common.HexToHash("0x36c10275e70689eb8e465ff89dfc95571f5c17baa4caf528b6b021eecde76993")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x281e7f87f3d6aa47e399cb08406605021a28c1be7226e3506d0dae792b7f3388")] = common.HexToHash("0xe88e2550f5f31ea3154f2ed21d0035954452f761758853acf640b12109061362")
	data[common.HexToHash("0x06c1a148fbb2b0f6a5b1ef9b5f5e76ff059b25b152ac60264e0a2d59df083226")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x490dcecb1c3fa0dcce60a2d8fdb1110931871a8b81169596f9931070eff49d89")] = common.HexToHash("0x0000000000000000000000000000000000000000000000008158855a700b4d18")
	data[common.HexToHash("0x776c33b39f89a952c8bf6a5b7c8880a7b546e6004f6e3d36fa63c300dd017032")] = common.HexToHash("0x8695faabf822020b69d7eee0cad41db7646abfb74332c4035fc3c510002452a3")
	data[common.HexToHash("0x737623345846fae5a1129d803037fa8fd3dfd54f114e43e403b22f4369e3ae99")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x6e2551c8e35e7df3d57889c548e081fde2766147d496af3cc1b2c45c8ac374ee")] = common.HexToHash("0x0000000000000000000000000000000000000000000000007e061aeb155f090b")
	data[common.HexToHash("0x96de09cb0cb20c61d464bc24c4a6ae789b0807d29a5d31b11c9db164874adbc5")] = common.HexToHash("0x00000000000000000000000000000000000000000000000096091973276908f3")
	data[common.HexToHash("0x18cd7397731ddab51183213b754d813b316f6c82f1ef033eb7d91a632c7b2413")] = common.HexToHash("0x46693f5e60e1d1a30c26fd0b157dcf708951d09edaa0aa62d86081c610d76258")
	data[common.HexToHash("0xde9331f9f326a1748b52dae5ca6126e7a66c0858454b7fe669618a8e05a9a371")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x87250d5b027f1bb5bf4027d838685dca1727394f9d46f567d5926405d649aded")] = common.HexToHash("0xc3daceffcbf3aa365ac39f7d339ec7bafa0654feac414bf39cee8a0137a25da8")
	data[common.HexToHash("0x36c10275e70689eb8e465ff89dfc95571f5c17baa4caf528b6b021eecde76994")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x33913de43aa2b09c194649e46f7617620ecc868cecedd41cf0445548438dffd1")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x281e7f87f3d6aa47e399cb08406605021a28c1be7226e3506d0dae792b7f338d")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x72f8edce16b1d47f1c34abf48ea3db8337721380789f3d9ecdbce854f08a6746")] = common.HexToHash("0xac420ad5f5df74759c8e81d5a3e282fc1048727b35cdc842ab815fc825785168")
	data[common.HexToHash("0xdd666736a8e576f4beeacd7f3cdef5e96f2319a92319c88ada1f772db741a08b")] = common.HexToHash("0x00000000000000000000000000000000f68e117541c57bd0ee532ce19fdc0dad")
	data[common.HexToHash("0x16979a4dee661d7096737f375799366189e5e84f18665bd8f66310ac99f935bd")] = common.HexToHash("0x00000000000000000000000000000000000000000000000093b96fe81a6929f8")
	data[common.HexToHash("0xcfe65a3eb077155e2524df4dd45db2f98532aed67a08dab5d007f4c2da71a1cc")] = common.HexToHash("0x00000000000000000000000000000000f715b137c5c795f21b576f522147be72")
	data[common.HexToHash("0x741fd89f11df0112dc19809e11522dbc03a9cbf3f9f2da933cb745ec9f1687a6")] = common.HexToHash("0x5ecb00d3f14ce2bf318f8cafd3fde6f5e66b3ae68ef1a0600f21b4bafb9ad5a6")
	data[common.HexToHash("0x36c39072f7fae573c3e0007f14a68ed0324710083fa87e55ead0adbb24db5ebc")] = common.HexToHash("0x00000000000000000000000000000000e45ee4072f64a771ef86404f30dcc41a")
	data[common.HexToHash("0x18dd1b5802a0c0f8f465a58b398dd1e3180808ccfecf57628325749767611977")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x72f8edce16b1d47f1c34abf48ea3db8337721380789f3d9ecdbce854f08a6749")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x68ff259936964d472fd8f07010a3bc1a732939d1e147b7017b022b47c88ca005")] = common.HexToHash("0x00000000000000000000000000000000be153f240c2563a196091973276908f3")
	data[common.HexToHash("0x06c1a148fbb2b0f6a5b1ef9b5f5e76ff059b25b152ac60264e0a2d59df083223")] = common.HexToHash("0x000000000000000000000000000000008158855a700b4d18b7686156a15ee267")
	data[common.HexToHash("0xfa0d6d0aaecb254018bfe12219afd4cc6f189d72f9db340053d2d60032944b54")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x18cd7397731ddab51183213b754d813b316f6c82f1ef033eb7d91a632c7b2412")] = common.HexToHash("0x1673b3e0597568358671aa4aa6eee1364c2088515c437c580851dde74e0f7d63")
	data[common.HexToHash("0x87250d5b027f1bb5bf4027d838685dca1727394f9d46f567d5926405d649adef")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000015")
	data[common.HexToHash("0x22ac82c898138e61b50dd482bdd1b6110173785cbab1cf938d21613cfed6770d")] = common.HexToHash("0x000000000000000000000000000000000000000000000000e48d8ee2baf2b2db")
	data[common.HexToHash("0x8e5b0e94df2f89afa53a46918f387ff6f72fd501b26ebd1185b4f4dd996b4d52")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0xde9331f9f326a1748b52dae5ca6126e7a66c0858454b7fe669618a8e05a9a373")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0xbef33da7fee60963d5fc2512cefacb93be3a8a3355396f665ca5a0b5efa423ce")] = common.HexToHash("0x000000000000000000000000000000000000000000000000e45ee4072f64a771")
	data[common.HexToHash("0xbf766c9947ee85772af554948694e6fa3526aff0345d5855c7bf2881c91070c8")] = common.HexToHash("0x00000000000000000000000000000000ee532ce19fdc0dadbe153f240c2563a1")
	data[common.HexToHash("0x18cd7397731ddab51183213b754d813b316f6c82f1ef033eb7d91a632c7b2416")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x33913de43aa2b09c194649e46f7617620ecc868cecedd41cf0445548438dffce")] = common.HexToHash("0x00000000000000000000000000000000680c8ae2c26696a193b96fe81a6929f8")
	data[common.HexToHash("0x776c33b39f89a952c8bf6a5b7c8880a7b546e6004f6e3d36fa63c300dd017034")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x737623345846fae5a1129d803037fa8fd3dfd54f114e43e403b22f4369e3ae97")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0xe34ec1f071cfffea0196b6be678b42e16fedd4984a9a8d790c712df7903f9ca0")] = common.HexToHash("0x000000000000000000000000000000000000000000000000a835081d57529a37")
	data[common.HexToHash("0xfa0d6d0aaecb254018bfe12219afd4cc6f189d72f9db340053d2d60032944b4f")] = common.HexToHash("0xcf717fda95412658d086019e2d50119695aa3ef9d88dd624da059064e636853e")
	data[common.HexToHash("0x737623345846fae5a1129d803037fa8fd3dfd54f114e43e403b22f4369e3ae98")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x33913de43aa2b09c194649e46f7617620ecc868cecedd41cf0445548438dffcd")] = common.HexToHash("0x74282d60fbbf2fd98f7bdad59a7d930a835946491cec9bf41f6b945b800f34b5")
	data[common.HexToHash("0x18dd1b5802a0c0f8f465a58b398dd1e3180808ccfecf57628325749767611978")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0xe212bf5e26869d4ad1f987da3d72c6c5e040d863543f1e82d23832d2ec7d27c0")] = common.HexToHash("0xbe153f240c2563a15cfcf69fe00fd6ea8c28f88150313ddd5757326c19cb0399")
	data[common.HexToHash("0x9c77aea8e544556df2d14dad9000bd6d022fbe44dd9639b33101518b8187e0d2")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0xc3e1944ebb08868868f424fb2a653c0859d02557391612c41aff6c9944a7f89a")] = common.HexToHash("0x0000000000000000000000000000000000000000000000001b576f522147be72")
	data[common.HexToHash("0xfa0d6d0aaecb254018bfe12219afd4cc6f189d72f9db340053d2d60032944b51")] = common.HexToHash("0x00000000000000000000000000000000a2bc05720344a278f68e117541c57bd0")
	data[common.HexToHash("0x9c77aea8e544556df2d14dad9000bd6d022fbe44dd9639b33101518b8187e0cd")] = common.HexToHash("0xf68e117541c57bd0790ee995911d6272ebcefc33fe32e7f1a5909e278b076185")
	data[common.HexToHash("0x9c77aea8e544556df2d14dad9000bd6d022fbe44dd9639b33101518b8187e0d1")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x8e5b0e94df2f89afa53a46918f387ff6f72fd501b26ebd1185b4f4dd996b4d50")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x68ff259936964d472fd8f07010a3bc1a732939d1e147b7017b022b47c88ca004")] = common.HexToHash("0x1729c63f77f53d54331a8b9d1c7ef8c4443f25e6c303a0dfbe4d36f053e9a7d5")
	data[common.HexToHash("0x68ff259936964d472fd8f07010a3bc1a732939d1e147b7017b022b47c88ca006")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x87ff5589d9ec65841e9fb186f9b43a7630cdd75faba888faa7af4fab212fb5f5")] = common.HexToHash("0x000000000000000000000000000000000000000000000000be153f240c2563a1")
	data[common.HexToHash("0xbf766c9947ee85772af554948694e6fa3526aff0345d5855c7bf2881c91070c7")] = common.HexToHash("0x2a10b07b69ba06d6eb409d3dcba81a98d93f679a18f8daddd09889cdd7dd4ee6")
	data[common.HexToHash("0xbf766c9947ee85772af554948694e6fa3526aff0345d5855c7bf2881c91070cb")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0xdd666736a8e576f4beeacd7f3cdef5e96f2319a92319c88ada1f772db741a08a")] = common.HexToHash("0x3670f3596f6769b802306c5928b270ef8e9d41ede8eb71bac058a16e70e0c22e")
	data[common.HexToHash("0x257e2cb2eb561b3f62d0f016d5ec069b41c7375eea79ed7eff294c6cef2c3f19")] = common.HexToHash("0x000000000000000000000000000000000000000000000000b7686156a15ee267")
	data[common.HexToHash("0x36c39072f7fae573c3e0007f14a68ed0324710083fa87e55ead0adbb24db5eba")] = common.HexToHash("0x680c8ae2c26696a11cde58e6f4ef49e0f70fa623a8102ded28a3bbe0276e775f")
	data[common.HexToHash("0x72f8edce16b1d47f1c34abf48ea3db8337721380789f3d9ecdbce854f08a6745")] = common.HexToHash("0x96091973276908f398306e8da90418b40eb370d94ff91b0670feb43842942767")
	data[common.HexToHash("0xe212bf5e26869d4ad1f987da3d72c6c5e040d863543f1e82d23832d2ec7d27c4")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x776c33b39f89a952c8bf6a5b7c8880a7b546e6004f6e3d36fa63c300dd017036")] = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000107ac00")
	data[common.HexToHash("0x68ff259936964d472fd8f07010a3bc1a732939d1e147b7017b022b47c88ca003")] = common.HexToHash("0xe48d8ee2baf2b2db9268d3c7f58ea16ac10602acda51e600d13e5ddf5d88e928")
	data[common.HexToHash("0x737623345846fae5a1129d803037fa8fd3dfd54f114e43e403b22f4369e3ae96")] = common.HexToHash("0x000000000000000000000000000000001673b3e059756835cf717fda95412658")
	data[common.HexToHash("0x18dd1b5802a0c0f8f465a58b398dd1e3180808ccfecf57628325749767611973")] = common.HexToHash("0xe45ee4072f64a771a0b80e3628a21a696fdf6f7caad449bd724a262934d05704")
	data[common.HexToHash("0xcfe65a3eb077155e2524df4dd45db2f98532aed67a08dab5d007f4c2da71a1ce")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	data[common.HexToHash("0x9c77aea8e544556df2d14dad9000bd6d022fbe44dd9639b33101518b8187e0d0")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x18cd7397731ddab51183213b754d813b316f6c82f1ef033eb7d91a632c7b2415")] = common.HexToHash("0x0000000000000000000000001dc3e354f2d72777e1226f1ed98d45e0de66e8e2")
	data[common.HexToHash("0x741fd89f11df0112dc19809e11522dbc03a9cbf3f9f2da933cb745ec9f1687a5")] = common.HexToHash("0xb7686156a15ee267c24dc2c9776a882f8db49d1bc7e5a5fb46352f495d8a2090")
	data[common.HexToHash("0xe212bf5e26869d4ad1f987da3d72c6c5e040d863543f1e82d23832d2ec7d27c1")] = common.HexToHash("0xb92f1506fe6b8cac4c08655260fb39aba52d2e1e4dc5c6632f23bccff20ec7ba")
	data[common.HexToHash("0x9c77aea8e544556df2d14dad9000bd6d022fbe44dd9639b33101518b8187e0cf")] = common.HexToHash("0x00000000000000000000000000000000cf717fda95412658f715b137c5c795f2")

	return GenesisAccount{
		Balance: big.NewInt(0),
		Nonce:   0,
		Storage: data,
		Code:    hexutil.MustDecode("0x60806040526004361061019d576000357c0100000000000000000000000000000000000000000000000000000000900480637ff69d3f116100ee578063c1292cc3116100a7578063da3c173a11610081578063da3c173a1461095e578063e781ecb914610997578063e91431f7146109ca578063ffdd5cf1146109df5761019d565b8063c1292cc3146108fb578063c27b27f414610910578063c2d20bad146109495761019d565b80637ff69d3f1461081e57806383d1b7861461085357806392eb1b401461089557806393822557146108aa578063a737b186146108bf578063aeb3d39b146108d45761019d565b80634fcbf5af1161015b578063641bd71a11610135578063641bd71a1461076457806373b150981461079d57806378583f23146107b25780637c6aeeef146107eb5761019d565b80634fcbf5af1461064c57806352b68cee146106b85780635d12e3611461070e5761019d565b8062b54ea6146104635780630cab529c1461048a57806316e7f1711461050257806319fe9a3b1461054a578063251c22d11461058357806331deb7e114610637575b3480156101a957600080fd5b503360009081526005602052604090205460c060020a02600160c060020a03198116158015906101f65750600160c060020a03198116600090815260046020819052604090912001546001145b1561046057600160c060020a03198116600090815260046020526040902060080154151561034957600160c060020a03198082166000908152600460205260408120600160089091018190556002805490910190555468010000000000000000900460c060020a0216156102ad576000805468010000000000000000900460c060020a908102600160c060020a0319168252600460205260409091206002018054600160c060020a03168284049092029190911790555b60008054600160c060020a031983168252600460205260408220600201805460c060020a680100000000000000009384900481028190047001000000000000000000000000000000000277ffffffffffffffff000000000000000000000000000000001990921691909117600160c060020a031690915582549084049091026fffffffffffffffff0000000000000000199091161790556103ea565b600160c060020a0319811660009081526004602052604081206007015411156103ea57600160c060020a0319811660009081526004602052604090206007015443036103208111156103bb57600160c060020a03198216600090815260046020526040902060016008909101556103e8565b600160c060020a031982166000908152600460205260409020600881018054830190556009018054820190555b505b600160c060020a0319811660009081526004602052604090204360078201556002015461043090700100000000000000000000000000000000900460c060020a02610a62565b600160c060020a031981166000908152600460205260409020600201546104609060c060020a9081900402610a62565b50005b34801561046f57600080fd5b50610478610d15565b60408051918252519081900360200190f35b34801561049657600080fd5b506104c3600480360360408110156104ad57600080fd5b50600160a060020a038135169060200135610d1b565b604051828152602081018260a080838360005b838110156104ee5781810151838201526020016104d6565b505050509050019250505060405180910390f35b34801561050e57600080fd5b506105366004803603602081101561052557600080fd5b5035600160c060020a031916610e26565b604080519115158252519081900360200190f35b34801561055657600080fd5b506104c36004803603604081101561056d57600080fd5b50600160a060020a038135169060200135610e71565b34801561058f57600080fd5b506105b7600480360360208110156105a657600080fd5b5035600160c060020a031916610f73565b604080519e8f5260208f019d909d52600160c060020a03199b8c168e8e0152998b1660608e0152978a1660808d015295891660a08c0152600160a060020a0390941660c08b015260e08a0192909252610100890152610120880152610140870152610160860152610180850152166101a083015251908190036101c00190f35b34801561064357600080fd5b5061047861100d565b34801561065857600080fd5b506106806004803603602081101561066f57600080fd5b5035600160c060020a03191661101b565b604051808260c080838360005b838110156106a557818101518382015260200161068d565b5050505090500191505060405180910390f35b3480156106c457600080fd5b506106f1600480360360408110156106db57600080fd5b50600160a060020a0381351690602001356110eb565b60408051600160c060020a03199092168252519081900360200190f35b34801561071a57600080fd5b506107486004803603604081101561073157600080fd5b50600160c060020a03198135169060200135611133565b60408051600160a060020a039092168252519081900360200190f35b34801561077057600080fd5b506106f16004803603604081101561078757600080fd5b50600160a060020a03813516906020013561116a565b3480156107a957600080fd5b50610478611185565b3480156107be57600080fd5b506106f1600480360360408110156107d557600080fd5b50600160a060020a03813516906020013561118b565b3480156107f757600080fd5b506104786004803603602081101561080e57600080fd5b5035600160a060020a03166111a6565b6108516004803603606081101561083457600080fd5b5080359060208101359060400135600160c060020a0319166111b8565b005b6108516004803603608081101561086957600080fd5b508035906020810135906040810135600160c060020a0319169060600135600160a060020a03166111c9565b3480156108a157600080fd5b50610478611859565b3480156108b657600080fd5b50610478611861565b3480156108cb57600080fd5b5061047861186d565b610851600480360360208110156108ea57600080fd5b5035600160c060020a031916611873565b34801561090757600080fd5b506106f1611a47565b34801561091c57600080fd5b506104c36004803603604081101561093357600080fd5b50600160a060020a038135169060200135611a53565b34801561095557600080fd5b50610478611b55565b34801561096a57600080fd5b506104786004803603604081101561098157600080fd5b50600160a060020a038135169060200135611b5b565b610851600480360360608110156109ad57600080fd5b5080359060208101359060400135600160c060020a031916611b7d565b3480156109d657600080fd5b506106f161233c565b3480156109eb57600080fd5b50610a1260048036036020811015610a0257600080fd5b5035600160a060020a0316612354565b604080519a8b5260208b0199909952898901979097526060890195909552608088019390935260a087019190915260c086015260e085015261010084015261012083015251908190036101400190f35b600160c060020a0319811615801590610a935750600160c060020a0319811660009081526004602052604090205415155b15610d12576015600254118015610ac55750600160c060020a0319811660009081526004602052604090206005015443115b15610c9557610ad3816123d9565b600160c060020a031980821660009081526004602052604090206002015460c060020a80820292680100000000000000009092040290821615610b5757600160c060020a03198216600090815260046020526040902060020180546fffffffffffffffff000000000000000019166801000000000000000060c060020a8404021790555b600160c060020a0319811615610b9f57600160c060020a031981166000908152600460205260409020600201805467ffffffffffffffff191660c060020a8404179055610bb9565b6000805467ffffffffffffffff191660c060020a84041790555b600160c060020a031983166000908152600460208190526040909120015460011415610c0157600160c060020a03198316600090815260046020819052604090912060029101555b6003805460019081018255600160c060020a0319851660008181526004602081815260408084209096018054600160a060020a039081168552600b8352878520805490970190965592849052908152905484519283529092169181019190915281517f86d1ab9dbf33cb06567fbeb4b47a6a365cf66f632380589591255187f5ca09cd929181900390910190a15050610d12565b600160c060020a03198116600090815260046020526040812060070154118015610cd95750600160c060020a03198116600090815260046020526040812060080154115b15610d1257600160c060020a0319811660009081526004602052604090206007015461032043919091031115610d1257610d12816123d9565b50565b60025481565b6000610d2561256b565b600160a060020a038416600090815260076020908152604091829020805483518184028101840190945280845260609392830182828015610db557602002820191906000526020600020906000905b82829054906101000a900460c060020a02600160c060020a03191681526020019060080190602082600701049283019260010382029150808411610d745790505b5050835196509293506000925050505b600581108015610dd6575083858201105b15610e1d5781858201815181101515610deb57fe5b60209081029091010151838260058110610e0157fe5b600160c060020a03199092166020929092020152600101610dc5565b50509250929050565b600160c060020a0319811660009081526004602052604081205415801590610e6b5750600160c060020a03198216600090815260046020819052604090912001546001145b92915050565b6000610e7b61256b565b600160a060020a038416600090815260066020908152604091829020805483518184028101840190945280845260609392830182828015610f0b57602002820191906000526020600020906000905b82829054906101000a900460c060020a02600160c060020a03191681526020019060080190602082600701049283019260010382029150808411610eca5790505b5050835196509293506000925050505b600581108015610f2c575083858201105b15610e1d5781858201815181101515610f4157fe5b60209081029091010151838260058110610f5757fe5b600160c060020a03199092166020929092020152600101610f1b565b600460208190526000918252604090912080546001820154600283015460038401549484015460058501546006860154600787015460088801546009890154600a909901549799969860c060020a808802996801000000000000000089048202997001000000000000000000000000000000008a04830299839004830298600160a060020a0390911697909690959094909390929091028e565b69021e19e0c9bab240000081565b61102361258a565b600160c060020a031982166000908152600a602090815260409182902080548351818402810184019094528084526060939283018282801561108e57602002820191906000526020600020905b8154600160a060020a03168152600190910190602001808311611070575b505083519394506000925050505b818110156110e35782818151811015156110b257fe5b602090810290910101518482600681106110c857fe5b600160a060020a03909216602092909202015260010161109c565b505050919050565b60076020528160005260406000208181548110151561110657fe5b9060005260206000209060049182820401919006600802915091509054906101000a900460c060020a0281565b600a6020528160005260406000208181548110151561114e57fe5b600091825260209091200154600160a060020a03169150829050565b60086020528160005260406000208181548110151561110657fe5b60015481565b60066020528160005260406000208181548110151561110657fe5b600b6020526000908152604090205481565b6111c4838383336111c9565b505050565b83600160c060020a03198116158015906111e257508315155b80156112055750600160c060020a03198116600090815260046020526040902054155b80156112295750600160c060020a0319831660009081526004602052604090205415155b801561123e575069021e19e0c9bab240000034145b151561124957600080fd5b6112516125a9565b6112596125c4565b8682526020808301879052816080846000600b600019f1151561127b57600080fd5b8051600160a060020a038116151561129257600080fd5b836005600083600160a060020a0316600160a060020a0316815260200190815260200160002060006101000a81548167ffffffffffffffff021916908360c060020a900402179055506101c0604051908101604052808981526020018881526020016000809054906101000a900460c060020a02600160c060020a0319168152602001600060c060020a02600160c060020a0319168152602001600060c060020a02600160c060020a0319168152602001600060c060020a02600160c060020a031916815260200186600160a060020a0316815260200160018152602001630107ac004301815260200143815260200160008152602001600081526020016000815260200187600160c060020a0319168152506004600086600160c060020a031916600160c060020a0319168152602001908152602001600020600082015181600001556020820151816001015560408201518160020160006101000a81548167ffffffffffffffff021916908360c060020a9004021790555060608201518160020160086101000a81548167ffffffffffffffff021916908360c060020a9004021790555060808201518160020160106101000a81548167ffffffffffffffff021916908360c060020a9004021790555060a08201518160020160186101000a81548167ffffffffffffffff021916908360c060020a9004021790555060c08201518160030160006101000a815481600160a060020a030219169083600160a060020a0316021790555060e08201518160040155610100820151816005015561012082015181600601556101408201518160070155610160820151816008015561018082015181600901556101a082015181600a0160006101000a81548167ffffffffffffffff021916908360c060020a90040217905550905050600060c060020a02600160c060020a0319166000809054906101000a900460c060020a02600160c060020a0319161415156115b45760008054600160c060020a031960c060020a91820216825260046020526040909120600201805491860468010000000000000000026fffffffffffffffff0000000000000000199092169190911790555b6000805467ffffffffffffffff191660c060020a86049081178255600160a060020a038716825260066020908152604083208054600181810183559185529184206004830401805467ffffffffffffffff60039094166008026101000a9384021916929093029190911790915580548101905586905b60068110156117c657600160c060020a0319808316600090815260046020908152604080832060030154938a168352600a825282208054600181018255908352912001805473ffffffffffffffffffffffffffffffffffffffff1916600160a060020a0390921691821790558115156116fb57600160a060020a03811660009081526007602090815260408220805460018101825590835291206004820401805467ffffffffffffffff60039093166008026101000a928302191660c060020a8a049290920291909117905561175f565b816001141561175f57600160a060020a03811660009081526008602081815260408320805460018101825590845292206004830401805460c060020a8b0460039094169092026101000a92830267ffffffffffffffff909302199091169190911790555b600160a060020a0381166000908152600960205260409020826006811061178257fe5b0180546001019055600160c060020a03199283166000908152600460205260409020600a015460c060020a0292831615156117bd57506117c6565b5060010161162a565b50604051600160a060020a03831690600090670de0b6b3a76400009082818181858883f19350505050158015611800573d6000803e3d6000fd5b5060408051600160c060020a031987168152600160a060020a038816602082015281517ff19f694d42048723a415f5eed7c402ce2c2e5dc0c41580c3f80e220db85ac389929181900390910190a1505050505050505050565b630107ac0081565b670de0b6b3a764000081565b61032081565b600160c060020a0319811660009081526004602081905260409091200154158015906118bd5750600160c060020a0319811660009081526004602081905260409091200154600314155b80156118d2575069021e19e0c9bab240000034145b80156119025750600160c060020a03198116600090815260046020526040902060030154600160a060020a031633145b151561190d57600080fd5b600160c060020a031981166000908152600460208190526040909120600581018054630107ac00019055015460021415610d1257600380546000199081018255600160c060020a0319808416600090815260046020908152604080832090950154600160a060020a03168252600b90529283208054909201909155905460c060020a0216156119e75760008054600160c060020a031960c060020a91820216825260046020526040909120600201805491830468010000000000000000026fffffffffffffffff0000000000000000199092169190911790555b6000805467ffffffffffffffff191660c060020a830417905560408051600160c060020a03198316815233602082015281517ff19f694d42048723a415f5eed7c402ce2c2e5dc0c41580c3f80e220db85ac389929181900390910190a150565b60005460c060020a0281565b6000611a5d61256b565b600160a060020a038416600090815260086020908152604091829020805483518184028101840190945280845260609392830182828015611aed57602002820191906000526020600020906000905b82829054906101000a900460c060020a02600160c060020a03191681526020019060080190602082600701049283019260010382029150808411611aac5790505b5050835196509293506000925050505b600581108015611b0e575083858201105b15610e1d5781858201815181101515611b2357fe5b60209081029091010151838260058110611b3957fe5b600160c060020a03199092166020929092020152600101611afd565b60035481565b60096020526000828152604090208160068110611b7457fe5b01549150829050565b82600160c060020a0319811615801590611b9657508315155b8015611ba157508215155b8015611bc45750600160c060020a03198116600090815260046020526040902054155b8015611be85750600160c060020a0319821660009081526004602052604090205415155b8015611c185750600160c060020a03198216600090815260046020526040902060030154600160a060020a031633145b8015611c3f5750600160c060020a0319821660009081526004602052604090206005015443105b8015611c52575034678ac7230489e80000145b1515611c5d57600080fd5b611c656125a9565b611c6d6125c4565b8582526020808301869052816080846000600b600019f11515611c8f57600080fd5b8051600160a060020a0381161515611ca657600080fd5b836005600083600160a060020a0316600160a060020a0316815260200190815260200160002060006101000a81548167ffffffffffffffff021916908360c060020a9004021790555060006004600087600160c060020a031916600160c060020a031916815260200190815260200160002060050154905060006004600088600160c060020a031916600160c060020a0319168152602001908152602001600020600a0160009054906101000a900460c060020a029050436004600089600160c060020a031916600160c060020a03191681526020019081526020016000206005018190555060036004600089600160c060020a031916600160c060020a0319168152602001908152602001600020600401819055506101c0604051908101604052808a81526020018981526020016000809054906101000a900460c060020a02600160c060020a0319168152602001600060c060020a02600160c060020a0319168152602001600060c060020a02600160c060020a0319168152602001600060c060020a02600160c060020a031916815260200133600160a060020a031681526020016001815260200183815260200143815260200160008152602001600081526020016000815260200182600160c060020a0319168152506004600088600160c060020a031916600160c060020a0319168152602001908152602001600020600082015181600001556020820151816001015560408201518160020160006101000a81548167ffffffffffffffff021916908360c060020a9004021790555060608201518160020160086101000a81548167ffffffffffffffff021916908360c060020a9004021790555060808201518160020160106101000a81548167ffffffffffffffff021916908360c060020a9004021790555060a08201518160020160186101000a81548167ffffffffffffffff021916908360c060020a9004021790555060c08201518160030160006101000a815481600160a060020a030219169083600160a060020a0316021790555060e08201518160040155610100820151816005015561012082015181600601556101408201518160070155610160820151816008015561018082015181600901556101a082015181600a0160006101000a81548167ffffffffffffffff021916908360c060020a90040217905550905050600060c060020a02600160c060020a0319166000809054906101000a900460c060020a02600160c060020a03191614151561208f5760008054600160c060020a031960c060020a91820216825260046020526040909120600201805491880468010000000000000000026fffffffffffffffff0000000000000000199092169190911790555b6000805467ffffffffffffffff191660c060020a8804908117825533825260066020908152604083208054600181810183559185529184206004830401805467ffffffffffffffff60039094166008026101000a9384021916929093029190911790915580548101905581905b600681101561226d57600160c060020a0319808316600090815260046020908152604080832060030154938c168352600a825282208054600181018255908352912001805473ffffffffffffffffffffffffffffffffffffffff1916600160a060020a0390921691821790558115156121cd57600160a060020a03811660009081526007602090815260408220805460018101825590835291206004820401805467ffffffffffffffff60039093166008026101000a928302191660c060020a8c0492909202919091179055612231565b816001141561223157600160a060020a03811660009081526008602081815260408320805460018101825590845292206004830401805460c060020a8d0460039094169092026101000a92830267ffffffffffffffff909302199091169190911790555b600160c060020a03199283166000908152600460205260409020600a015460c060020a029283161515612264575061226d565b506001016120fc565b50604051600160a060020a03851690600090670de0b6b3a76400009082818181858883f193505050501580156122a7573d6000803e3d6000fd5b5060408051600160c060020a03198a16815233602082015281517f86d1ab9dbf33cb06567fbeb4b47a6a365cf66f632380589591255187f5ca09cd929181900390910190a160408051600160c060020a03198916815233602082015281517ff19f694d42048723a415f5eed7c402ce2c2e5dc0c41580c3f80e220db85ac389929181900390910190a150505050505050505050565b60005468010000000000000000900460c060020a0281565b600180546002805460038054600160a060020a03969096166000908152600b602090815260408083205460068352818420546009909352922080549781015460058201546004830154958301549290970154670de0b6b3a76400003031049b600a60304302049b999a9799989486900397959692948587019092019093019091010190565b600160c060020a031981166000908152600460205260408120600801541115610d125760028054600019018155600160c060020a0319808316600090815260046020526040812060088101919091559091015460c060020a70010000000000000000000000000000000082048102929181900402908216156124b457600160c060020a031982811660009081526004602052604080822060029081018054600160c060020a031660c060020a808804021790559286168252902001805477ffffffffffffffff00000000000000000000000000000000191690555b600160c060020a031981161561253857600160c060020a03198181166000908152600460205260408082206002908101805477ffffffffffffffff00000000000000000000000000000000191670010000000000000000000000000000000060c060020a89040217905592861682529020018054600160c060020a031690556111c4565b6000805460c060020a840468010000000000000000026fffffffffffffffff000000000000000019909116179055505050565b60a0604051908101604052806005906020820280388339509192915050565b60c0604051908101604052806006906020820280388339509192915050565b60408051808201825290600290829080388339509192915050565b602060405190810160405280600190602082028038833950919291505056fea165627a7a7230582087358faea8aceee5d1e78e343fa3a741b0218c07ee740e767a586f73e806dcb70029"),
	}
}
