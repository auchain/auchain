// Copyright 2018 The go-auc Authors
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

// Package circum implements the proof-of-stake consensus engine.
package circum

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/auchain/auchain/common"
	"github.com/auchain/auchain/consensus"
	"github.com/auchain/auchain/consensus/misc"
	"github.com/auchain/auchain/core/state"
	"github.com/auchain/auchain/core/types"
	"github.com/auchain/auchain/crypto"
	"github.com/auchain/auchain/crypto/sha3"
	"github.com/auchain/auchain/ethdb"
	"github.com/auchain/auchain/log"
	"github.com/auchain/auchain/params"
	"github.com/auchain/auchain/rlp"
	"github.com/auchain/auchain/rpc"
	"github.com/hashicorp/golang-lru"
	"math"
)

const (
	extraVanity        = 32   // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal          = 65   // Fixed number of extra-data suffix bytes reserved for signer seal
	inmemorySnapshots  = 128  // Number of recent snapshots to keep in memory
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory
)

var (
	blockReward     = big.NewInt(47500e+14) // Block reward in wei to masternode account when successfully mining a block
	referrerRewards = []*big.Int{
		new(big.Int).SetUint64(237500000000000000),
		new(big.Int).SetUint64(261250000000000000),
		new(big.Int).SetUint64(130625000000000000),
		new(big.Int).SetUint64(65312500000000000),
		new(big.Int).SetUint64(32656250000000000),
		new(big.Int).SetUint64(16328125000000000),
	}
	rewardPeriod uint64 = 10512000
	confirmedBlockHead = []byte("confirmed-block-head")
	uncleHash          = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")
	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")
	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte suffix signature missing")
	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")
	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash  = errors.New("non empty uncle hash")
	errInvalidDifficulty = errors.New("invalid difficulty")
	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp         = errors.New("invalid timestamp")
	ErrInvalidBlockWitness      = errors.New("invalid block witness")
	ErrMinerFutureBlock         = errors.New("miner the future block")
	ErrWaitForPrevBlock         = errors.New("wait for last block arrived")
	ErrWaitForRightTime         = errors.New("wait for right time")
	ErrNilBlockHeader           = errors.New("nil block header returned")
	ErrMismatchSignerAndWitness = errors.New("mismatch block signer and witness")
	ErrInvalidMinerBlockTime    = errors.New("invalid time to miner the block")
)

// SignerFn
// string:master node nodeid,[8]byte
// []byte,signature
type SignerFn func(string, []byte) ([]byte, error)

type MasternodeListFn func(number *big.Int) ([]string, error)

// NOTE: sigHash was copy from clique
// sigHash returns the hash which is used as input for the proof-of-authority
// signing. It is the hash of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func sigHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewKeccak256()

	rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Witness,
		header.Coinbase,
		header.Referrers,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	})
	hasher.Sum(hash[:0])
	return hash
}

type Circum struct {
	config *params.CircumConfig // Consensus engine configuration parameters
	db     ethdb.Database       // Database to store and retrieve snapshot checkpoints

	signer     string          // master node nodeid
	signFn     SignerFn        // signature function
	recents    *lru.ARCCache   // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache   // Signatures of recent blocks to speed up mining
	proposals  map[string]bool // Current list of proposals we are pushing

	confirmedBlockHeader *types.Header
	masternodeListFn     MasternodeListFn //get current all masternodes
	mu                   sync.RWMutex
	lock                 sync.RWMutex
	stop                 chan bool
}

func NewCircum(config *params.CircumConfig, db ethdb.Database) *Circum {
	// Allocate the snapshot caches and create the engine
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)
	return &Circum{
		config:     config,
		db:         db,
		signatures: signatures,
		recents:    recents,
		proposals:  make(map[string]bool),
	}
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (d *Circum) Prepare(chain consensus.ChainReader, header *types.Header) error {
	header.Nonce = types.BlockNonce{}
	number := header.Number.Uint64()
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = d.CalcDifficulty(chain, header.Time, parent)
	header.Witness = d.signer
	return nil
}

// AccumulateRewards credits the coinbase of the given block with the mining
// reward.  The circum consensus allowed uncle block .
func AccumulateRewards(state *state.StateDB, header *types.Header) {
	currentPeriod := header.Number.Uint64() / rewardPeriod
	if currentPeriod > 6 {
		currentPeriod = 6
	}
	currentPeriod1 := float64(currentPeriod)
	rate := new(big.Int).SetUint64(uint64(math.Pow(0.5, currentPeriod1) * 100000000))
	blockReward1 := new(big.Int).Mul(blockReward, rate)
	blockReward2 := new(big.Int).Div(blockReward1, big.NewInt(100000000))
	state.AddBalance(header.Coinbase, blockReward2, header.Number)
	for i, ref := range header.Referrers {
		referrerReward1 := new(big.Int).Mul(referrerRewards[i], rate)
		referrerReward2 := new(big.Int).Div(referrerReward1, big.NewInt(100000000))
		state.AddBalance(ref, referrerReward2, header.Number)
	}
}

func (d *Circum) getStableBlockNumber(number *big.Int) (*big.Int) {
	stableBlockNumber := new(big.Int).Sub(number, big.NewInt(21))
	if stableBlockNumber.Cmp(big.NewInt(int64(params.GenesisBlockNumber))) < 0 {
		return big.NewInt(int64(params.GenesisBlockNumber))
	}
	return stableBlockNumber
}

// Finalize implements consensus.Engine, accumulating the block and uncle rewards,
// setting the final state and assembling the block.
func (d *Circum) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	parent := chain.GetHeaderByHash(header.ParentHash)
	// Accumulate block rewards and commit the final state root
	AccumulateRewards(state, header)
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	stableBlockNumber := d.getStableBlockNumber(parent.Number)
	nodes, err := d.masternodeListFn(stableBlockNumber)
	if err != nil {
		return nil, fmt.Errorf("Get current masternodes failed from contract\n%s", err)
	}
	d.signatures.Add(header.Number.Uint64(), nodes)

	//accumulating the signer of block
	log.Debug("rolling ", "Number", header.Number, "parentTime", parent.Time, "headerTime", header.Time, "witness", header.Witness)
	return types.NewBlock(header, txs, uncles, receipts), nil
}
// Author implements consensus.Engine, returning the header's coinbase as the
// proof-of-stake verified author of the block.
func (d *Circum) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// verifyHeader checks whether a header conforms to the consensus rules of the
// stock circum engine.
func (d *Circum) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return d.verifyHeader(chain, header, nil)
}

func (d *Circum) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()
	// Unnecssary to verify the block from feature
	if int64(header.Time) > time.Now().Unix() {
		return consensus.ErrFutureBlock
	}
	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Difficulty always 1
	if header.Difficulty.Uint64() != 1 {
		return errInvalidDifficulty
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in circum
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		log.Error("circum consensus verifyHeader was failed ", "err", err)
		return err
	}

	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	//if parent.Time+params.Period > header.Time {
	//	return ErrInvalidTimestamp
	//}
	return nil
}

func (d *Circum) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := d.verifyHeader(chain, header, headers[:i])
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (d *Circum) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (d *Circum) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return d.verifySeal(chain, header, nil)
}

func (d *Circum) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}

	witness, err := d.lookup(header.Time, parent)
	if err != nil {
		return err
	}
	if err := d.verifyBlockSigner(witness, header); err != nil {
		return err
	}
	return d.updateConfirmedBlockHeader(chain)
}

func (d *Circum) verifyBlockSigner(witness string, header *types.Header) error {
	signer, err := ecrecover(header, d.signatures)
	if err != nil {
		return err
	}
	if signer != witness {
		return fmt.Errorf("invalid block witness signer: %s,witness: %s\n", signer, witness)
	}
	if signer != header.Witness {
		return ErrMismatchSignerAndWitness
	}
	return nil
}

func (d *Circum) checkTime(lastBlock *types.Block, now uint64) error {
	prevSlot := PrevSlot(now)
	nextSlot := NextSlot(now)
	if lastBlock.Time() >= nextSlot {
		return ErrMinerFutureBlock
	}
	// last block was arrived, or time's up
	if lastBlock.Time() == prevSlot || nextSlot-now <= 1 {
		return nil
	}
	return ErrWaitForPrevBlock
}

func (d *Circum) CheckWitness(lastBlock *types.Block, now int64) error {
	if err := d.checkTime(lastBlock, uint64(now)); err != nil {
		return err
	}

	witness, err := d.lookup(uint64(now), lastBlock.Header())
	if err != nil {
		return err
	}
	if (witness == "") || witness != d.signer {
		return ErrInvalidBlockWitness
	}
	logTime := time.Now().Format("[2006-01-02 15:04:05]")
	fmt.Printf("%s [%s] 🔨 It's my turn!\n", logTime, witness)
	return nil
}

func (d *Circum) lookup(now uint64, lastBlock *types.Header) (string, error) {
	stableBlockNumber := d.getStableBlockNumber(lastBlock.Number)
	nodes, err := d.masternodeListFn(stableBlockNumber)
	if err != nil {
		return "", fmt.Errorf("Get current masternodes failed from contract\n%s", err)
	}
	nextNth := ((now - params.GenesisTime) / params.Period) % uint64(len(nodes))
	// fmt.Println(now, params.GenesisTime, (now - params.GenesisTime) / params.Period, nextNth, lastBlock.Witness)
	nodesmap := make(map[string]int)
	for i, witness := range nodes {
		nodesmap[witness] = i
	}
	lastNth := nodesmap[lastBlock.Witness]
	if lastBlock.Time > now {
		return "", fmt.Errorf("lookup error time")
	}
	if nextNth == uint64(lastNth) {
		return "", ErrWaitForRightTime
	}
	return nodes[nextNth], nil
}

// Seal generates a new block for the given input block with the local miner's
// seal place on top.
func (d *Circum) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	header := block.Header()
	number := header.Number.Uint64()
	// Sealing the genesis block is not supported
	if number == 0 {
		return nil, errUnknownBlock
	}
	// Don't hold the signer fields for the entire sealing procedure
	d.lock.RLock()
	signFn := d.signFn
	d.lock.RUnlock()

	// time's up, sign the block
	sighash, err := signFn(d.signer, sigHash(header).Bytes())
	if err != nil {
		return nil, err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)
	return block.WithSeal(header), nil
}

func (d *Circum) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return big.NewInt(1)
}

func (d *Circum) Authorize(signer string, signFn SignerFn) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.signer = signer
	d.signFn = signFn
	log.Info("Circum Authorize ", "signer", signer)
}

func (d *Circum) Masternodes(masternodeListFn MasternodeListFn) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.masternodeListFn = masternodeListFn
}

// ecrecover extracts the Masternode account ID from a signed header.
func ecrecover(header *types.Header, sigcache *lru.ARCCache) (string, error) {
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return "", errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]
	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(sigHash(header).Bytes(), signature)
	if err != nil {
		return "", err
	}
	id := fmt.Sprintf("%x", pubkey[1:9])
	return id, nil
}

func (d *Circum) updateConfirmedBlockHeader(chain consensus.ChainReader) error {
	if d.confirmedBlockHeader == nil {
		header, err := d.loadConfirmedBlockHeader(chain)
		if err != nil {
			header = chain.GetHeaderByNumber(params.GenesisBlockNumber)
			if header == nil {
				return err
			}
		}
		d.confirmedBlockHeader = header
	}

	curHeader := chain.CurrentHeader()
	witnessMap := make(map[string]bool)
	consensusSize := int(15)
	for d.confirmedBlockHeader.Hash() != curHeader.Hash() &&
		d.confirmedBlockHeader.Number.Uint64() < curHeader.Number.Uint64() {
		// fast return
		// if block number difference less consensusSize-witnessNum
		// there is no need to check block is confirmed
		if curHeader.Number.Int64()-d.confirmedBlockHeader.Number.Int64() < int64(consensusSize-len(witnessMap)) {
			log.Debug("Circum fast return", "current", curHeader.Number.String(), "confirmed", d.confirmedBlockHeader.Number.String(), "witnessCount", len(witnessMap))
			return nil
		}
		witnessMap[curHeader.Witness] = true
		if len(witnessMap) >= consensusSize {
			d.confirmedBlockHeader = curHeader
			if err := d.storeConfirmedBlockHeader(d.db); err != nil {
				return err
			}
			log.Debug("circum set confirmed block header success", "currentHeader", curHeader.Number.String())
			return nil
		}
		curHeader = chain.GetHeaderByHash(curHeader.ParentHash)
		if curHeader == nil {
			return ErrNilBlockHeader
		}
	}
	return nil
}

// store inserts the snapshot into the database.
func (d *Circum) storeConfirmedBlockHeader(db ethdb.Database) error {
	db.Put(confirmedBlockHead, d.confirmedBlockHeader.Hash().Bytes())
	return nil
}

func (d *Circum) loadConfirmedBlockHeader(chain consensus.ChainReader) (*types.Header, error) {

	key, err := d.db.Get(confirmedBlockHead)
	if err != nil {
		return nil, err
	}
	header := chain.GetHeaderByHash(common.BytesToHash(key))
	if header == nil {
		return nil, ErrNilBlockHeader
	}
	return header, nil
}

func PrevSlot(now uint64) uint64 {
	return (now - 1) / params.Period * params.Period
}

func NextSlot(now uint64) uint64 {
	return ((now + params.Period - 1) / params.Period) * params.Period
}

// APIs implements consensus.Engine, returning the user facing RPC APIs.
func (d *Circum) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "circum",
		Version:   "1.0",
		Service:   &API{chain: chain, circum: d},
		Public:    true,
	}}
}

// Close implements consensus.Engine. It's a noop for Circum as there is are no background threads.
func (d *Circum) Close() error {
	return nil
}

// SealHash returns the hash of a block prior to it being sealed.
func (d *Circum) SealHash(header *types.Header) common.Hash {
	return sigHash(header)
}

func (d *Circum) SetCircumDB(db ethdb.Database) {
	d.db = db
}
