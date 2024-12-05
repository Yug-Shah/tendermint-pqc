package privval

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/dilithium"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
	"github.com/tendermint/tendermint/crypto/tmhash"
	cryptoproto "github.com/tendermint/tendermint/proto/tendermint/crypto"
	privproto "github.com/tendermint/tendermint/proto/tendermint/privval"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	"github.com/tendermint/tendermint/types"
)

var stamp = time.Date(2019, 10, 13, 16, 14, 44, 0, time.UTC)

func exampleVote() *types.Vote {
	return &types.Vote{
		Type:      tmproto.SignedMsgType(1),
		Height:    3,
		Round:     2,
		Timestamp: stamp,
		BlockID: types.BlockID{
			Hash: tmhash.Sum([]byte("blockID_hash")),
			PartSetHeader: types.PartSetHeader{
				Total: 1000000,
				Hash:  tmhash.Sum([]byte("blockID_part_set_header_hash")),
			},
		},
		ValidatorAddress: crypto.AddressHash([]byte("validator_address")),
		ValidatorIndex:   56789,
	}
}

func exampleProposal() *types.Proposal {

	return &types.Proposal{
		Type:      tmproto.SignedMsgType(1),
		Height:    3,
		Round:     2,
		Timestamp: stamp,
		POLRound:  2,
		Signature: []byte("it's a signature"),
		BlockID: types.BlockID{
			Hash: tmhash.Sum([]byte("blockID_hash")),
			PartSetHeader: types.PartSetHeader{
				Total: 1000000,
				Hash:  tmhash.Sum([]byte("blockID_part_set_header_hash")),
			},
		},
	}
}

//nolint:lll // ignore line length for tests
func TestPrivvalVectors(t *testing.T) {
	// pk := ed25519.GenPrivKeyFromSecret([]byte("it's a secret")).PubKey()
	pk := dilithium.GenPrivKeyFromSeed([]byte("it's a secret")).PubKey()
	ppk, err := cryptoenc.PubKeyToProto(pk)
	require.NoError(t, err)

	// Generate a simple vote
	vote := exampleVote()
	votepb := vote.ToProto()

	// Generate a simple proposal
	proposal := exampleProposal()
	proposalpb := proposal.ToProto()

	// Create a Reuseable remote error
	remoteError := &privproto.RemoteSignerError{Code: 1, Description: "it's a error"}

	testCases := []struct {
		testName string
		msg      proto.Message
		expBytes string
	}{
		{"ping request", &privproto.PingRequest{}, "3a00"},
		{"ping response", &privproto.PingResponse{}, "4200"},
		{"pubKey request", &privproto.PubKeyRequest{}, "0a00"},
		// Uncomment to test for ed25519 keys
		// {"pubKey response", &privproto.PubKeyResponse{PubKey: ppk, Error: nil}, "12240a220a20556a436f1218d30942efe798420f51dc9b6a311b929c578257457d05c5fcf230"},
		{"pubKey response", &privproto.PubKeyResponse{PubKey: ppk, Error: nil}, "12a60a0aa30a1aa00acd06ecc8572bd7a943985575b3502399003c30149fc1bc6f16b7873ad43cce8353fe4690fa235318786ffda858ee1c706a2d6e5132065138c018cd1bcc05cfcee09cf67c52aac19702a1b843fb24f4d9046d4bd5936132511cf62db28982dc82d5d7d2cef92091e77ca3ef7e0025ab44d80e428cd32fa1e9b0996b251313063688c014cd61d1f4a1468eeeea9f02f886ff71b8f26f73c91e52f249a9a7cf8f1eaf3bc153870c98f96c6c8316563c44d4af8c14a614c7cbd3233a2bec5ee71885772fc2ba1fd5abdce635dbf833dbc5bf40097c686d75c18b3279450b3a6ea9e628049091ee04aa781ab83095570181f1a4ed85f3fbef69725cdc681a6a23e8ae3612d3fefa3fbc84820b9cb6cdd2beb698025665d215127c6cd4285f9049a2c11ce1cf39e6fb5534118a2191e51ff495b9cea71c7a9a28e79984e53dfc8ef8b335cf8d100754de51586d3eddfe451fd748df855fc6a27b0d9d8671ca56060890dcd23b9e85762b3bf369a4d7001e763cac8b621ef944194524a3f6c9d707973b50102bfc73ef4872174f2b5d19097f6a2c71b2a79233dbe3d9f1e3abd640b502f2287490bbf6be659f468c7f27c9e792cfa0d3790a625e4be6befa5715a9967cfd8df37766629429643d89879cd02d00192a64f287f47eb168b0a58b4a7940a5f6579c84f05d3c0a828c393b6c4b55e93ecfd1f80ab5d50fc7a7fdc479c78099e7041271b7a2696ee75892852acb5d93ddd0bac616de69b7ef279e77ecf8f07a6a61d3b0549fc1867d7c745d788f67d36ea648e5eeee0ad265c2063be549e53a3634eef21bf1bde681f6816d4e397f96fbe705a088ff26745f762f00b0fd5299492e7eb4e18a00778016338dd76c6ce241e352c5024768183b314ee21f440220ada72fc17d5d63a21e0d50ca8815d878656d4648ca2d784f141e3840bf1b3b525e1c2c8d8ba2f1d448acfee53610664fafd255e617110a530f798ba295771abd12a6aecece94ea0d917c09d49d8c50b1a60256b31400e7477f82f824a12f56d269749b5e2fb03d54212099f4a2136b7a5064560e5df85759738f0c323f305782a2c7c5e4770a21896d4d4741a77d73bf857822ac4db63354a9413918700f0a9a2ef6cbb545223342c6cfaec9eb0b2763440f4bc4d2f5977e6d2bfb28ba43e133bd02d1cc8575a1f357b213638eeb4d04ae14a0b601c1b7ecc26077813b12e78d75fd0c2886911c1a63dcbf64283e284fa9eb3a121a3ef400fdbe38b3544704a70b1e69479f4f9c6bb4d4076466687da2b204bd97f02af5b925ded74a933ae645ea2099c94dae0b9c1608fdba4c6439cbc9fce8a48f8be6e046a948fa939d981a5e11e74605d4be8661c5b3f1a40905012d8903be7b132f61c488352da0ffe421decf4e52e3f8561681fc8088391ceb19bb6d1310fc0f1c8ed0504e667befd3dc2a83df95661e039f8d0c714d1a36736bfa86d1f57d5f9c281fdc06441c98b289ed15f2ce8aa2dd85ab71a73ff94e08b5626a61be0eca6c673c5030c0a5a171d028d77a5e107a7b4f278deb56ac97fd355715d1841013024429923955a76bcd2b3b4bf52d468cd5779377e4a4d94929250f86e6e9a450500338524af62c76e8f99542fcb75e306c00f72e9a291c862c954e97be7a61b832849aa0c89295fa0668ce917afc4863dda0344de7565a20d0ef4411e3cb5166e2efb8dd136fdcff5906d5be398426f079e466434ea5f856f582fc69a29de7e04dd8cdfec667ad61d3d8466839a027c2bc077f3d88fd9861e2bfae196f3fc9c083949554ea61440238c88b35e47859795e17bc533b1f03d279aa1c1a9459425db5965bef8375787764c3"},
		{"pubKey response with error", &privproto.PubKeyResponse{PubKey: cryptoproto.PublicKey{}, Error: remoteError}, "12140a0012100801120c697427732061206572726f72"},
		{"Vote Request", &privproto.SignVoteRequest{Vote: votepb}, "1a760a74080110031802224a0a208b01023386c371778ecb6368573e539afc3cc860ec3a2f614e54fe5652f4fc80122608c0843d122072db3d959635dff1bb567bedaa70573392c5159666a3f8caf11e413aac52207a2a0608f49a8ded0532146af1f4111082efb388211bc72c55bcd61e9ac3d538d5bb03"},
		{"Vote Response", &privproto.SignedVoteResponse{Vote: *votepb, Error: nil}, "22760a74080110031802224a0a208b01023386c371778ecb6368573e539afc3cc860ec3a2f614e54fe5652f4fc80122608c0843d122072db3d959635dff1bb567bedaa70573392c5159666a3f8caf11e413aac52207a2a0608f49a8ded0532146af1f4111082efb388211bc72c55bcd61e9ac3d538d5bb03"},
		{"Vote Response with error", &privproto.SignedVoteResponse{Vote: tmproto.Vote{}, Error: remoteError}, "22250a11220212002a0b088092b8c398feffffff0112100801120c697427732061206572726f72"},
		{"Proposal Request", &privproto.SignProposalRequest{Proposal: proposalpb}, "2a700a6e08011003180220022a4a0a208b01023386c371778ecb6368573e539afc3cc860ec3a2f614e54fe5652f4fc80122608c0843d122072db3d959635dff1bb567bedaa70573392c5159666a3f8caf11e413aac52207a320608f49a8ded053a10697427732061207369676e6174757265"},
		{"Proposal Response", &privproto.SignedProposalResponse{Proposal: *proposalpb, Error: nil}, "32700a6e08011003180220022a4a0a208b01023386c371778ecb6368573e539afc3cc860ec3a2f614e54fe5652f4fc80122608c0843d122072db3d959635dff1bb567bedaa70573392c5159666a3f8caf11e413aac52207a320608f49a8ded053a10697427732061207369676e6174757265"},
		{"Proposal Response with error", &privproto.SignedProposalResponse{Proposal: tmproto.Proposal{}, Error: remoteError}, "32250a112a021200320b088092b8c398feffffff0112100801120c697427732061206572726f72"},
	}

	for _, tc := range testCases {
		tc := tc

		pm := mustWrapMsg(tc.msg)
		bz, err := pm.Marshal()
		require.NoError(t, err, tc.testName)

		require.Equal(t, tc.expBytes, hex.EncodeToString(bz), tc.testName)
	}
}
