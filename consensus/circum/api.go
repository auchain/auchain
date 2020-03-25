// Copyright 2018 The auc Authors
// This file is part of the auc library.
//
// The auc library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The auc library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the auc library. If not, see <http://www.gnu.org/licenses/>.

// Package circum implements the proof-of-authority consensus engine.
package circum

import (
	"math/big"

	"github.com/auchain/auchain/consensus"
)
// API is a user facing RPC API to allow controlling the delegate and voting
// mechanisms of the delegated-proof-of-stake
type API struct {
	chain consensus.ChainReader
	circum  *Circum
}

// GetConfirmedBlockNumber retrieves the latest irreversible block
func (api *API) GetConfirmedBlockNumber() (*big.Int, error) {
	var err error
	header := api.circum.confirmedBlockHeader
	if header == nil {
		header, err = api.circum.loadConfirmedBlockHeader(api.chain)
		if err != nil {
			return nil, err
		}
	}
	return header.Number, nil
}

// Proposals returns the current proposals the node tries to uphold and vote on.
func (api *API) Proposals() map[string]bool {
	api.circum.lock.RLock()
	defer api.circum.lock.RUnlock()

	proposals := make(map[string]bool)
	for signer, auth := range api.circum.proposals {
		proposals[signer] = auth
	}
	return proposals
}

// Propose injects a new authorization proposal that the signer will attempt to
// push through.
func (api *API) Propose(signer string, auth bool) {
	api.circum.lock.Lock()
	defer api.circum.lock.Unlock()

	api.circum.proposals[signer] = auth
}

// Discard drops a currently running proposal, stopping the signer from casting
// further votes (either for or against).
func (api *API) Discard(signer string) {
	api.circum.lock.Lock()
	defer api.circum.lock.Unlock()

	delete(api.circum.proposals, signer)
}
